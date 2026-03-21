# Standard library
import time

# Third-party libraries
from colorama import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules + MCP
import UTILITIES
import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS

# Build the Log Analytics Client
law_client = LogsQueryClient(credential=DefaultAzureCredential())

# Build the OpenAI client
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)

# Default model
model = MODEL_MANAGEMENT.DEFAULT_MODEL

mode = input(
    "\nChoose mode:\n"
    "1. Natural language hunt\n"
    "2. Raw KQL query\n"
    "> "
).strip()

if mode == "2":
    raw_kql = input("\nPaste your KQL query:\n").strip()

    print(f"\n{Fore.LIGHTGREEN_EX}Running raw KQL query...\n")

    law_query_results = EXECUTOR.query_log_analytics_raw(
        log_analytics_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        user_query=raw_kql
    )

    user_prompt_for_ai = f"The user supplied this raw KQL query:\n{raw_kql}"

    table_name_for_prompt = "RawKQL"
else:
    # Natural language mode
    user_message = PROMPT_MANAGEMENT.get_user_message()

    unformatted_query_context = EXECUTOR.get_query_context(
        openai_client, user_message, model=model
    )

    query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

    UTILITIES.display_query_context(query_context)

    GUARDRAILS.validate_tables_and_fields(
        query_context["table_name"], query_context["fields"]
    )

    law_query_results = EXECUTOR.query_log_analytics(
        log_analytics_client=law_client,
        workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
        timerange_hours=query_context["time_range_hours"],
        table_name=query_context["table_name"],
        device_name=query_context["device_name"],
        fields=query_context["fields"],
        caller=query_context["caller"],
        start_time=query_context["start_time"],
        end_time=query_context["end_time"],
        user_principal_name=query_context["user_principal_name"]
    )

    user_prompt_for_ai = user_message["content"]
    table_name_for_prompt = query_context["table_name"]

number_of_records = law_query_results["count"]

print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

if number_of_records == 0:
    print("Exiting.")
    exit(0)

threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
    user_prompt=user_prompt_for_ai,
    table_name=table_name_for_prompt,
    log_data=law_query_results["records"]
)

threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT
threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model)
model = MODEL_MANAGEMENT.choose_model(model, number_of_tokens)

GUARDRAILS.validate_model(model)
print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targeted logs...\n")

start_time = time.time()

hunt_results = EXECUTOR.hunt(
    openai_client=openai_client,
    threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=threat_hunt_user_message,
    openai_model=model
)

if not hunt_results:
    exit()

elapsed = time.time() - start_time

print(
    f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found "
    f"{Fore.LIGHTRED_EX}{len(hunt_results['findings'])} {Fore.WHITE}potential threat(s)!\n"
)

input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results.")

UTILITIES.display_threats(threat_list=hunt_results["findings"])