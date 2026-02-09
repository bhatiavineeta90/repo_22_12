import sys
import json
import os
import configparser
from pymongo import MongoClient, DESCENDING

def get_config():
    cfg = configparser.ConfigParser()
    paths = [
        os.path.join(os.path.dirname(__file__), "..", "config", "config.ini"),
        "config/config.ini",
    ]
    for p in paths:
        if os.path.exists(p):
            cfg.read(p)
            return cfg
    return cfg

def fmt(doc):
    if not doc: return "null"
    d = dict(doc)
    d.pop('_id', None)
    return json.dumps(d, indent=2, default=str)

def show_runs(db):
    runs = list(db.rt_runs.find().sort("started_at", DESCENDING))
    if not runs:
        print("no runs found")
        return
    print(f"\n{'run_id':<40} {'payload':<20} {'status':<10}")
    print("-"*75)
    for r in runs:
        print(f"{r.get('run_id','')[:38]:<40} {r.get('payload_name','')[:18]:<20} {r.get('status','')}")
    print(f"\nusage: python {sys.argv[0]} <run_id>")

def show_by_run(db, rid):
    print(f"\n=== RUN: {rid} ===")
    run = db.rt_runs.find_one({"run_id": rid})
    if run:
        print(fmt(run))
    else:
        print("run not found")
        return
    
    print("\n=== ATTACKS ===")
    for a in db.rt_attack_execution.find({"run_id": rid}):
        print(f"\n[{a.get('attack_name')}]")
        print(fmt(a))
    
    print("\n=== VULNS ===")
    for v in db.rt_vulnerability_execution.find({"run_id": rid}):
        print(f"\n[{v.get('vulnerability_name')}]")
        print(fmt(v))
    
    print("\n=== RESULTS ===")
    results = list(db.rt_results.find({"run_id": rid}).sort("turn", 1))
    print(f"total: {len(results)}")
    for r in results:
        print(f"\n-- turn {r.get('turn')} --")
        print(fmt(r))

def main():
    cfg = get_config()
    try:
        uri = cfg.get("mongodb", "uri")
        dbname = cfg.get("mongodb", "database_name")
    except:
        print("error: check config/config.ini [mongodb] section")
        return
    
    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=3000)
        client.admin.command('ping')
    except Exception as e:
        print(f"mongodb connection failed: {e}")
        return
    
    db = client[dbname]
    
    if len(sys.argv) > 1:
        show_by_run(db, sys.argv[1])
    else:
        show_runs(db)
    
    client.close()

if __name__ == "__main__":
    main()
