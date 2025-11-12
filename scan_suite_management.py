from __future__ import annotations

import json5
import requests
import argparse
import time
import os

def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return json5.load(f)

# ---------- BUILD CREATE MUTATION ----------
def build_create_mutation(config: dict, owner_id: str) -> str:
    scan_name = f"{owner_id}_{config['scheduleJobConfiguration']['name']}_Passive_Scan"
    description = config.get("description", "")
    policy_id = config["policyId"]
    environment = config["trafficEnvironment"]
    hook_id = config["hookConfiguration"].strip()
    adv = config.get("advanceConfiguration", {})

    # Normalize schedule config
    schedule_name = config["scheduleJobConfiguration"]["name"].upper()
    schedule_time = config["scheduleJobConfiguration"]["dailySchedule"]["scheduledTime"]

    # Debug output
    print(f"🧩 Using Hook ID: {hook_id}")
    print(f"🕒 Schedule Name: {schedule_name}")
    print(f"🕒 Schedule Time: {schedule_time}")

    mutation = f"""
    mutation {{
      createScanSuite(
        create: {{
          name: "{scan_name}"
          description: "{description}"
          environment: "{environment}"
          configuration: {{
            assetSelections: [
              {{
                selectionMode: INCLUDE
                selectedAsset: FILTER_RULE
                selectedAssetFilter: [
                  {{
                    keyExpression: {{ key: "owner" }}
                    operator: IN
                    value: ["{owner_id}"]
                    type: ATTRIBUTE
                  }}
                ]
              }},
              {{
                selectionMode: INCLUDE
                selectedAsset: ENDPOINT
                endpoint: {{
                  urlPredicates: [
                    {{ relationalOperator: MATCHES_REGEX, value: ".+" }}
                  ]
                }}
              }},
              {{
                selectionMode: EXCLUDE
                selectedAsset: ENDPOINT
                endpoint: {{
                  urlPredicates: [
                    {{ relationalOperator: MATCHES_REGEX, value: ".*(logout|health).*" }}
                  ]
                }}
              }}
            ]
            policyId: "{policy_id}"
            targetUrl: ""
            trafficConfiguration: {{ generationTrafficType: LIVE_TRAFFIC }}
            trafficEnvironment: "{environment}"
            spanFilters: {{ conditions: [] }}
          }}
          advanceConfiguration: {{
            delayDurationBetweenRequests: "{adv.get("delayDurationBetweenRequests", "PT0S")}"
            idleTimeoutDuration: "{adv.get("idleTimeoutDuration", "PT600S")}"
            scanTimeoutDuration: "{adv.get("scanTimeoutDuration", "PT1800S")}"
            totalTestExecutionThreads: {adv.get("totalTestExecutionThreads", 20)}
          }}
          hookConfiguration: {{
            hookDetails: [{{ hookId: "{hook_id}" }}]
          }}
          integrationDetails: []
          scanEvaluationCriteriaConfiguration: {{
            scanEvaluationCriteriaDetails: [
              {{
                inlineScanEvaluationCriteriaDetails: {{
                  expression: {{ allEvaluateTrue: false }}
                  rules: [
                    {{
                      assetScope: {{
                        assetType: ENDPOINT
                        assetSelection: {{ selectAllAssets: {{ isEnabled: true }} }}
                      }}
                      vulnerabilityScopeAndEvaluation: {{
                        operator: GREATER_THAN
                        severity: HIGH
                        threshold: 0
                        vulnerabilitySelection: {{
                          selectAnyVulnerability: {{ isEnabled: true }}
                        }}
                      }}
                    }}
                  ]
                }}
              }}
            ]
          }}
          scheduleJobConfiguration: {{
            status: ENABLED
            name: ""
            runnerIds: []
            runnerLabels: []
            dailySchedule: {{ scheduledTime: "{schedule_time}" }}
          }}
        }}
      ) {{
        id
        __typename
      }}
    }}
    """
    return mutation

# ---------- EXECUTE MUTATION ----------
def run_mutation(endpoint: str, token: str, mutation: str, owner_id: str):
    headers = {"Authorization": f"{token}", "Content-Type": "application/json"}

    # Save the GQL mutation to a file for inspection
    gql_filename = f"create_suite_{owner_id}.gql"
    with open(gql_filename, "w") as f:
        f.write(mutation)
    print(f"🪵 GraphQL mutation logged → {gql_filename}")

    response = requests.post(endpoint, headers=headers, json={"query": mutation})

    try:
        result = response.json()
    except Exception:
        print(f"❌ Response for Owner {owner_id} was not valid JSON.")
        print("Raw response:\n", response.text)
        return None

    # Log raw response
    log_file = f"create_suite_{owner_id}.log"
    with open(log_file, "w") as f:
        f.write(json5.dumps(result, indent=2))
    print(f"🪵 Response logged → {log_file}")

    if "errors" in result:
        for err in result["errors"]:
            msg = err.get("message", "")
            code = err.get("extensions", {}).get("code", "")
            if "not unique across all environments" in msg and code == 6:
                print(f"⚠️  Suite for {owner_id} already exists. Skipping...")
            else:
                print(f"❌ Error for {owner_id}: {msg}")
        return None
    return result

# ---------- SEARCH + DELETE ----------
def build_search_query(name_pattern: str | None, offset: int = 0) -> str:
    # Always include a minimal filter to keep the query valid, but
    # only include SCAN_SUITE_NAME when we actually want to filter by prefix.
    filters = [
        '{ key: SCAN_RUN_NUMBER, operator: GREATER_THAN_OR_EQUAL_TO, value: 0 }'
    ]
    if name_pattern is not None:
        filters.append(f'{{ key: SCAN_SUITE_NAME, operator: LIKE, value: "{name_pattern}" }}')

    filters_block = ",\n".join(filters)

    return f"""
    {{
      searchAst(
        astDataSource: SCANS,
        limit: 100,
        offset: {offset},
        filterBy: [
          {filters_block}
        ],
        orderBy: {{ key: SCAN_START_TIME, direction: DESC }}
      ) {{
        count
        total
        results {{
          SCAN_SUITE_NAME: selection(key: SCAN_SUITE_NAME) {{ value }}
          SCAN_SUITE_ID: selection(key: SCAN_SUITE_ID) {{ value }}
        }}
      }}
    }}
    """


def delete_scan_suites(endpoint: str, token: str, suite_ids: list):
    ids = ", ".join([f'"{sid}"' for sid in suite_ids])
    mutation = f"""
    mutation {{
      deleteScanSuites(scanSuiteIdList: [{ids}]) {{
        success
        __typename
      }}
    }}
    """

    print("\n📤 GraphQL mutation being sent:")
    print(mutation)

    headers = {"Authorization": f"{token}", "Content-Type": "application/json"}
    response = requests.post(endpoint, headers=headers, json={"query": mutation})

    try:
        result = response.json()
        print("📥 Raw response:")
        print(json5.dumps(result, indent=2))
        if result.get("data", {}).get("deleteScanSuites", {}).get("success"):
            print(f"✅ Deleted {len(suite_ids)} scan suites successfully.")
        else:
            print("⚠️ Unexpected delete response format or failure.")
        return result
    except Exception:
        print("❌ Failed to parse delete response.")
        print(response.text)

def search_and_delete(config, endpoint, token):
    delete_cfg = config.get("deleteConfig", {})
    owner_input = (delete_cfg.get("ownerValue") or "").strip()
    safe_delete = bool(delete_cfg.get("safeDelete", True))
    dry_run = bool(delete_cfg.get("dryRun", False))

    headers = {"Authorization": f"{token}", "Content-Type": "application/json"}

    # Normalize the target list
    if owner_input.lower() == "all":
        owner_ids = ["__ALL__"]
    else:
        owner_ids = [oid.strip() for oid in owner_input.split(",") if oid.strip()]

    for owner_id in owner_ids:
        # When deleting ALL: do not filter by SCAN_SUITE_NAME at all
        if owner_id == "__ALL__":
            name_pattern = None
            owner_label = "ALL"
        else:
            # Prefix match for per-owner suites like "AD00007..._"
            name_pattern = f"{owner_id}_"
            owner_label = owner_id

        all_suites, offset = [], 0
        while True:
            query = build_search_query(name_pattern, offset)
            resp = requests.post(endpoint, headers=headers, json={"query": query})
            try:
                data = resp.json()
            except Exception:
                print("❌ Failed to parse searchAst response. Raw:\n", resp.text)
                break

            # Defensive checks
            results = (
                data.get("data", {})
                    .get("searchAst", {})
                    .get("results", [])
            )

            if not results:
                break

            all_suites.extend(results)
            offset += 100
            if len(results) < 100:
                break

        if not all_suites:
            print(f"⚠️  No matching suites found for {owner_label.lower()}.")
            continue

        # Print summary
        print(f"🔍 Found {len(all_suites)} scan suites for {owner_label}")
        seen_names = set()
        for suite in all_suites:
            nm = suite["SCAN_SUITE_NAME"]["value"]
            if nm not in seen_names:
                print(f" - {nm}")
                seen_names.add(nm)

        # Dedup IDs
        suite_ids = list(set([r["SCAN_SUITE_ID"]["value"] for r in all_suites]))
        if len(suite_ids) < len(all_suites):
            print("⚠️ Duplicate suite IDs detected and removed before deletion.")

        if dry_run:
            print(f"🧪 DRY RUN: Would delete {len(suite_ids)} suites for {owner_label}. No changes made.")
            # Still log what would be deleted
            with open("deleted_suites.log", "a") as log:
                for suite in all_suites:
                    log.write(f"{time.ctime()} | DRYRUN | {owner_label} | {suite['SCAN_SUITE_NAME']['value']}\n")
            continue

        if safe_delete:
            confirm = input(f"❓ Delete {len(suite_ids)} suites for {owner_label}? (yes/no): ")
            if confirm.strip().lower() != "yes":
                print("⏭️  Skipping deletion.")
                continue
        else:
            print(f"🚀 safeDelete=false → deleting {len(suite_ids)} suites for {owner_label} without prompt.")

        # Perform deletion
        delete_scan_suites(endpoint, token, suite_ids)

        # Log actual deletions
        with open("deleted_suites.log", "a") as log:
            for suite in all_suites:
                log.write(f"{time.ctime()} | {owner_label} | {suite['SCAN_SUITE_NAME']['value']}\n")


# ---------- MAIN ----------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", required=True, choices=["create", "delete"], help="Mode to run the script in.")
    args = parser.parse_args()

    config = load_config("scan_config.json5")
    endpoint = config["graphqlEndpoint"]
    token = config["token"]

    if args.mode == "create":
        owner_ids = [oid.strip() for oid in config["ownerValue"].split(",")]
        for owner_id in owner_ids:
            print(f"\nCreating scan suite for Owner ID: {owner_id}")
            mutation = build_create_mutation(config, owner_id)
            result = run_mutation(endpoint, token, mutation, owner_id)
            if result:
                print(json5.dumps(result, indent=2))
    elif args.mode == "delete":
        search_and_delete(config, endpoint, token)

if __name__ == "__main__":
    main()
