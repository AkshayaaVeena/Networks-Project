import pymongo

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["update_channel_db"]
results_collection = db["results"]

def save_result(data):
    results_collection.insert_one(data)

def get_all_results():
    return list(results_collection.find({}, {"_id": 0}))
