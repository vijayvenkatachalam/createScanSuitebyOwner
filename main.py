import json5
import requests

def load_config(path: str) -> dict:
    with open(path, 'r') as f:
        return json5.load(f)

def build_mutation(config: dict, owner_id: str) -> str:
    scan_name = f"{owner_id}_{config['scheduleJobConfiguration']['name']}_Passive_Scan"
    description = config.get("description", "")
    policy_id = config["policyId"]
    environment = config["trafficEnvironment"]
    hook_id = config["hookConfiguration"]
    schedule_time = config["scheduleJobConfiguration"]["dailySchedule"]["scheduledTime"]

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
              }}
            ]
            policyId: "{policy_id}"
            targetUrl: ""
            trafficConfiguration: {{ generationTrafficType: REPLAY_TRAFFIC }}
            trafficEnvironment: "{environment}"
            spanFilters: {{ conditions: [] }}
          }}
          advanceConfiguration: {{
            delayDurationBetweenRequests: "PT0S"
            idleTimeoutDuration: "PT600S"
            scanTimeoutDuration: "PT1800S"
            totalTestExecutionThreads: 20
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
                        vulnerabilityDurationScope: {{
                          maximumVulnerabilityDuration: {{
                            vulnerabilityOpenDuration: "PT604800S"
                          }}
                        }}
                      }}
                    }},
                    {{
                      assetScope: {{
                        assetType: SERVICE
                        assetSelection: {{ selectAllAssets: {{ isEnabled: true }} }}
                      }}
                      vulnerabilityScopeAndEvaluation: {{
                        operator: GREATER_THAN
                        severity: HIGH
                        threshold: 0
                        vulnerabilitySelection: {{
                          selectAnyVulnerability: {{ isEnabled: true }}
                        }}
                        vulnerabilityDurationScope: {{
                          maximumVulnerabilityDuration: {{
                            vulnerabilityOpenDuration: "PT604800S"
                          }}
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
            name: "{config['scheduleJobConfiguration']['name']}"
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

def run_mutation(endpoint: str, token: str, mutation: str, owner_id: str):
    headers = {
        "Authorization": f"{token}",
        "Content-Type": "application/json"
    }

    response = requests.post(endpoint, headers=headers, json={"query": mutation})

    try:
        result = response.json()
    except requests.exceptions.JSONDecodeError:
        print(f"❌ Response for Owner {owner_id} was not valid JSON.")
        print("Raw response:\n", response.text)
        return None

    if "errors" in result:
        for err in result["errors"]:
            msg = err.get("message", "")
            code = err.get("extensions", {}).get("code", "")
            if "not unique across all environments" in msg and code == 6:
                print(f"⚠️  Suite for {owner_id} already exists. Skipping...")
                return None
            else:
                print(f"❌ Unexpected error for {owner_id}: {msg}")
        return None

    return result

def main():
    config = load_config("scan_config.json5")
    endpoint = config["graphqlEndpoint"]
    token = config["token"]
    owner_ids = [oid.strip() for oid in config["ownerValue"].split(",")]

    for owner_id in owner_ids:
        print(f"\nCreating scan suite for Owner ID: {owner_id}")
        mutation = build_mutation(config, owner_id)
        result = run_mutation(endpoint, token, mutation, owner_id)
        if result:
            print(json5.dumps(result, indent=2))

if __name__ == "__main__":
    main()
