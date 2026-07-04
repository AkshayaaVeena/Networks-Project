"""Unit tests for the pure scoring/analysis functions in analyze.py.

These don't require a live capture, MongoDB, or tshark - they test the
business logic in isolation, which is the part most worth covering since
it encodes the actual security-scoring decisions.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import json
from unittest.mock import patch, MagicMock

import analyze
from analyze import (
    score_cipher,
    check_forward_secrecy,
    check_certificate,
    is_suspicious_domain,
    calculate_app_score,
    analyze_pcap,
)


class TestScoreCipher:
    def test_tls13_aes_gcm_scores_highest(self):
        assert score_cipher("TLS_AES_256_GCM_SHA384") == 40

    def test_chacha20_scores_well(self):
        assert score_cipher("TLS_CHACHA20_POLY1305_SHA256") == 30

    def test_ecdhe_gcm_scores_moderately(self):
        assert score_cipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == 20

    def test_ecdhe_cbc_scores_lower_than_gcm(self):
        assert score_cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA") == 15

    def test_weak_legacy_ciphers_score_minimally(self):
        for weak in ["RC4", "3DES", "NULL-MD5", "EXPORT_RC4_40"]:
            assert score_cipher(weak) == 5

    def test_none_cipher_scores_zero(self):
        assert score_cipher(None) == 0

    def test_unrecognized_cipher_scores_zero(self):
        assert score_cipher("SOME_MADE_UP_CIPHER") == 0

    def test_case_insensitive(self):
        assert score_cipher("tls_aes_128_gcm_sha256") == score_cipher("TLS_AES_128_GCM_SHA256")


class TestForwardSecrecy:
    def test_ecdhe_grants_forward_secrecy_points(self):
        assert check_forward_secrecy("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256") == 20

    def test_dhe_grants_forward_secrecy_points(self):
        assert check_forward_secrecy("TLS_DHE_RSA_WITH_AES_128_GCM_SHA256") == 20

    def test_rsa_only_has_no_forward_secrecy(self):
        assert check_forward_secrecy("TLS_RSA_WITH_AES_128_GCM_SHA256") == 0

    def test_none_cipher_has_no_forward_secrecy(self):
        assert check_forward_secrecy(None) == 0


class TestCheckCertificate:
    def test_self_signed_is_weak(self):
        assert check_certificate("self-signed") == "Weak"

    def test_trusted_is_strong(self):
        assert check_certificate("trusted") == "Strong"

    def test_unknown_defaults_to_medium(self):
        assert check_certificate("something-else") == "Medium"
        assert check_certificate(None) == "Medium"


class TestSuspiciousDomain:
    def test_known_suspicious_domain_flagged(self):
        assert is_suspicious_domain("tracker.com") is True

    def test_case_insensitive_match(self):
        assert is_suspicious_domain("TRACKER.COM") is True

    def test_legitimate_domain_not_flagged(self):
        assert is_suspicious_domain("google.com") is False


class TestCalculateAppScore:
    def _app_data(self, sessions, quic_used=False):
        return {"tls_sessions": sessions, "quic_used": quic_used}

    def test_no_sessions_scores_zero(self):
        result = calculate_app_score(self._app_data([]))
        assert result["score"] == 0
        assert result["session_details"] == []

    def test_strong_tls13_session_scores_high(self):
        session = {
            "tls_version": "TLS 1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_strength": "Strong",
            "uses_http": False,
            "suspicious_domain": False,
        }
        result = calculate_app_score(self._app_data([session]))
        assert result["score"] > 80

    def test_http_session_is_penalized(self):
        secure = {
            "tls_version": "TLS 1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_strength": "Strong",
            "uses_http": False,
            "suspicious_domain": False,
        }
        insecure = {**secure, "uses_http": True}

        secure_score = calculate_app_score(self._app_data([secure]))["score"]
        insecure_score = calculate_app_score(self._app_data([insecure]))["score"]
        assert insecure_score < secure_score

    def test_suspicious_domain_is_penalized(self):
        clean = {
            "tls_version": "TLS 1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_strength": "Strong",
            "uses_http": False,
            "suspicious_domain": False,
        }
        suspicious = {**clean, "suspicious_domain": True}

        clean_score = calculate_app_score(self._app_data([clean]))["score"]
        suspicious_score = calculate_app_score(self._app_data([suspicious]))["score"]
        assert suspicious_score < clean_score

    def test_quic_usage_adds_bonus(self):
        session = {
            "tls_version": "TLS 1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
            "certificate_strength": "Medium",
            "uses_http": False,
            "suspicious_domain": False,
        }
        without_quic = calculate_app_score(self._app_data([session], quic_used=False))["score"]
        with_quic = calculate_app_score(self._app_data([session], quic_used=True))["score"]
        assert with_quic >= without_quic

    def test_session_with_no_tls_or_cipher_info_is_skipped(self):
        session = {
            "tls_version": "Unknown",
            "cipher": None,
            "certificate_strength": "Medium",
            "uses_http": False,
            "suspicious_domain": False,
        }
        result = calculate_app_score(self._app_data([session]))
        assert result["session_details"][0]["note"] == "Skipped - no TLS/cipher info"
        assert result["score"] == 0

    def test_score_is_bounded_0_to_100(self):
        session = {
            "tls_version": "TLS 1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "certificate_strength": "Strong",
            "uses_http": False,
            "suspicious_domain": False,
        }
        result = calculate_app_score(self._app_data([session], quic_used=True))
        assert 0 <= result["score"] <= 100


class TestAnalyzePcapSerializationSafety:
    """Regression tests for a bug where a mid-capture failure left
    `domains_contacted` as a raw Python set, which Flask's jsonify() (and
    MongoDB's BSON encoder) can't serialize - causing /latest to 500 with
    an opaque error after an otherwise-successful capture.
    """

    def _make_fake_capture(self, packets, raise_after=None):
        """Build a fake pyshark capture that yields `packets`, optionally
        raising partway through to simulate a malformed-record failure."""

        def generator():
            for i, pkt in enumerate(packets):
                if raise_after is not None and i == raise_after:
                    raise RuntimeError("Simulated malformed packet mid-stream")
                yield pkt

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: generator()
        return fake_cap

    def test_clean_run_is_json_serializable(self):
        pkt = MagicMock()
        pkt.ip = True
        pkt.tls.handshake_extensions_server_name = "example.com"
        pkt.tls.record_version = "0x0303"
        pkt.tls.handshake_ciphersuite = None
        pkt.tls.handshake_certificate = None
        del pkt.tcp
        del pkt.quic
        del pkt.http

        fake_cap = self._make_fake_capture([pkt])
        with patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            result = analyze_pcap()

        json.dumps(result)
        assert "error" not in result

    def test_mid_stream_failure_still_produces_serializable_result(self):
        pkt = MagicMock()
        pkt.ip = True
        pkt.tls.handshake_extensions_server_name = "example.com"
        pkt.tls.record_version = "0x0303"
        pkt.tls.handshake_ciphersuite = None
        pkt.tls.handshake_certificate = None
        del pkt.tcp
        del pkt.quic
        del pkt.http



        fake_cap = self._make_fake_capture([pkt, pkt], raise_after=1)
        with patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            result = analyze_pcap()

        assert "error" in result
        json.dumps(result)
        for app_data in result["apps"].values():
            assert isinstance(app_data["domains_contacted"], list)

    def test_filecapture_itself_failing_still_returns_serializable_result(self):
        with patch("analyze.pyshark.FileCapture", side_effect=RuntimeError("no such file")):
            result = analyze_pcap()

        assert "error" in result
        json.dumps(result)


class TestFlowBasedAppAttribution:
    """Regression tests for a bug where only the packet carrying the TLS
    ClientHello SNI got attributed to the right app - every other packet in
    that same connection (the vast majority of real traffic) fell back to
    "unknown_app", because app name was resolved per-packet instead of
    per-connection.
    """

    def _make_pkt(self, sni=None, src="10.0.0.5", dst="93.184.216.34",
                   sport="51000", dport="443", flags="0x0010", seq="100",
                   timestamp="1000.0"):
        pkt = MagicMock()
        pkt.ip.src = src
        pkt.ip.dst = dst
        pkt.tcp.srcport = sport
        pkt.tcp.dstport = dport
        pkt.tcp.flags = flags
        pkt.tcp.seq = seq
        pkt.sniff_timestamp = timestamp
        pkt.tls.record_version = "0x0303"
        pkt.tls.handshake_ciphersuite = None
        pkt.tls.handshake_certificate = None
        if sni:
            pkt.tls.handshake_extensions_server_name = sni
        else:
            del pkt.tls.handshake_extensions_server_name
        del pkt.quic
        del pkt.http
        return pkt

    def test_later_packets_in_same_flow_inherit_app_name_from_sni(self):



        pkt1 = self._make_pkt(sni="example.com", seq="100")
        pkt2 = self._make_pkt(sni=None, seq="200")
        pkt3 = self._make_pkt(sni=None, seq="300")

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: iter([pkt1, pkt2, pkt3])

        with patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            result = analyze_pcap()

        assert "unknown_app" not in result["apps"] or len(result["apps"]["unknown_app"]["tls_sessions"]) == 0
        assert len(result["apps"]["example"]["tls_sessions"]) == 3

    def test_syn_and_synack_share_the_same_flow_despite_swapped_direction(self):



        syn = self._make_pkt(src="10.0.0.5", dst="93.184.216.34",
                              sport="51000", dport="443", flags="SYN", seq="1",
                              timestamp="1000.000")
        synack = self._make_pkt(src="93.184.216.34", dst="10.0.0.5",
                                 sport="443", dport="51000", flags="SYN, ACK", seq="1",
                                 timestamp="1000.050")

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: iter([syn, synack])

        with patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            result = analyze_pcap()




        total_delay = sum(app["average_delay"] for app in result["apps"].values())
        assert total_delay > 0


class TestPacketLossCalculation:
    """Regression tests for a bug where packet loss was computed from the
    span of TCP sequence numbers as if it were a packet count, instead of a
    byte count - which made any healthy connection with normal-sized
    (~1400 byte) segments look like ~99% packet loss.
    """

    def _make_data_pkt(self, seq, seg_len, src="10.0.0.5", dst="93.184.216.34",
                        sport="51000", dport="443", timestamp="1000.0"):
        pkt = MagicMock()
        pkt.ip.src = src
        pkt.ip.dst = dst
        pkt.tcp.srcport = sport
        pkt.tcp.dstport = dport
        pkt.tcp.flags = "PSH, ACK"
        pkt.tcp.seq = str(seq)
        pkt.tcp.len = str(seg_len)
        pkt.sniff_timestamp = timestamp
        pkt.tls.record_version = "0x0303"
        pkt.tls.handshake_ciphersuite = None
        pkt.tls.handshake_certificate = None
        del pkt.tls.handshake_extensions_server_name
        del pkt.quic
        del pkt.http
        return pkt

    def test_fully_covered_flow_with_large_segments_reports_zero_loss(self):




        pkts = [self._make_data_pkt(seq=i * 1400, seg_len=1400) for i in range(5)]

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: iter(pkts)

        with patch("analyze.NOTIFICATION_LOG") as mock_log,             patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            mock_log.exists.return_value = False
            result = analyze.analyze_pcap()

        assert result["apps"]["unknown_app"]["packet_loss"] == 0

    def test_flow_with_an_actual_gap_reports_nonzero_loss(self):


        pkts = [self._make_data_pkt(seq=i * 1400, seg_len=1400) for i in [0, 1, 3, 4]]

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: iter(pkts)

        with patch("analyze.NOTIFICATION_LOG") as mock_log,             patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            mock_log.exists.return_value = False
            result = analyze.analyze_pcap()

        assert result["apps"]["unknown_app"]["packet_loss"] > 0


class TestSummaryScore:
    """Regression tests for a bug where apps with zero observed traffic
    (only ever appeared in the notification log) were scored 0 and folded
    into the summary average, dragging it toward 0 regardless of how secure
    the apps that *were* actually observed were.
    """

    def test_unmeasured_apps_do_not_drag_down_summary_score(self):
        analysis_pkt = MagicMock()
        analysis_pkt.ip.src = "10.0.0.5"
        analysis_pkt.ip.dst = "93.184.216.34"
        analysis_pkt.tcp.srcport = "51000"
        analysis_pkt.tcp.dstport = "443"
        analysis_pkt.tcp.flags = "PSH, ACK"
        analysis_pkt.tcp.seq = "0"
        analysis_pkt.tcp.len = "100"
        analysis_pkt.sniff_timestamp = "1000.0"
        analysis_pkt.tls.handshake_extensions_server_name = "secure-app.com"
        analysis_pkt.tls.record_version = "0x0304"
        analysis_pkt.tls.handshake_ciphersuite.showname_value = "TLS_AES_256_GCM_SHA384"
        analysis_pkt.tls.handshake_certificate = None
        del analysis_pkt.quic
        del analysis_pkt.http

        fake_cap = MagicMock()
        fake_cap.__iter__ = lambda self: iter([analysis_pkt])

        with patch("analyze.NOTIFICATION_LOG") as mock_log,             patch("analyze.pyshark.FileCapture", return_value=fake_cap):
            mock_log.exists.return_value = False
            result = analyze.analyze_pcap()




        assert result["summary_score"] > 50

    def test_app_with_no_sessions_is_marked_unmeasured(self):
        with patch("analyze.NOTIFICATION_LOG") as mock_log:
            mock_log.exists.return_value = True
            with patch("builtins.open", create=True) as mock_open:
                mock_open.return_value.__enter__.return_value = iter(
                    ['{"app": "some.app"}\n']
                )
                with patch("analyze.pyshark.FileCapture", side_effect=RuntimeError("no capture")):
                    result = analyze.analyze_pcap()

        assert result["apps"]["some.app"]["measured"] is False
