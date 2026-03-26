import json
from colorama import Fore, Style, init

def display_incident(incident):
    init(autoreset=True)

    print("\n" + "=" * 70)
    print(f"{Fore.LIGHTRED_EX}🚨 INCIDENT REPORT{Style.RESET_ALL}")
    print("=" * 70)

    # Incident Summary
    summary = incident.get("incident_summary", {})
    print(f"\n{Fore.LIGHTCYAN_EX}== Incident Summary =={Style.RESET_ALL}")
    print(f"Overview      : {summary.get('overview')}")
    print(f"Primary User  : {summary.get('primary_user')}")
    print(f"Primary Host  : {summary.get('primary_host')}")
    print(f"{Fore.LIGHTRED_EX}Severity      : {summary.get('severity')}{Style.RESET_ALL}")

    # Scope of Compromise
    scope = incident.get("scope_of_compromise", {})
    print(f"\n{Fore.LIGHTCYAN_EX}== Scope of Compromise =={Style.RESET_ALL}")
    for key, values in scope.items():
        print(f"\n{key.upper()}:")
        for v in values:
            print(f"  - {v}")

    # Attack Timeline
    timeline = incident.get("attack_timeline", [])
    print(f"\n{Fore.LIGHTCYAN_EX}== Attack Timeline =={Style.RESET_ALL}")
    for event in timeline:
        print(f"\n[{event.get('timestamp')}]")
        print(f"{Fore.LIGHTYELLOW_EX}{event.get('action')}{Style.RESET_ALL}")
        print(f"Details      : {event.get('details')}")
        if event.get("source_table"):
            print(f"Source Table : {event.get('source_table')}")

    # Attacker Activity
    activities = incident.get("attacker_activity", [])
    print(f"\n{Fore.LIGHTCYAN_EX}== Attacker Activity =={Style.RESET_ALL}")
    for activity in activities:
        print("\n" + "-" * 60)
        print(f"{Fore.LIGHTMAGENTA_EX}{activity.get('category')}{Style.RESET_ALL}")
        print(f"Description: {activity.get('description')}")

        if activity.get("event_count") is not None:
            print(f"\nEvent Count: {activity.get('event_count')}")

        if activity.get("distinct_files"):
            print("\nDistinct Files:")
            for f in activity.get("distinct_files", []):
                print(f"  - {f}")

        if activity.get("distinct_destinations"):
            print("\nDistinct Destinations:")
            for d in activity.get("distinct_destinations", []):
                print(f"  - {d}")

        print("\nEvidence:")
        for e in activity.get("evidence", []):
            print(f"  - {e}")

        mitre = activity.get("mitre", {})
        print("\nMITRE:")
        print(f"  Tactic    : {mitre.get('tactic')}")
        print(f"  Technique : {mitre.get('technique')}")
        print(f"  ID        : {mitre.get('id')}")

        print("\nIOCs:")
        for ioc in activity.get("iocs", []):
            print(f"  - {ioc}")

    # Impact Assessment
    impact = incident.get("impact_assessment", {})
    print(f"\n{Fore.LIGHTCYAN_EX}== Impact Assessment =={Style.RESET_ALL}")
    for key, value in impact.items():
        color = Fore.LIGHTRED_EX if value else Fore.LIGHTGREEN_EX
        print(f"{color}{key}: {value}{Style.RESET_ALL}")

    # Further Investigation
    investigations = incident.get("further_investigation", [])
    print(f"\n{Fore.LIGHTCYAN_EX}== Further Investigation =={Style.RESET_ALL}")
    for item in investigations:
        print("\n" + "-" * 60)
        print(f"Purpose     : {item.get('purpose')}")
        print(f"Table       : {item.get('table')}")
        print(f"Timestamp   : {item.get('timestamp')}")
        print(f"Time Window : {item.get('time_window')}")
        print(f"Why         : {item.get('why')}")

        guidance = item.get("search_guidance", [])
        if guidance:
            print("Search Guidance:")
            for g in guidance:
                print(f"  - {g}")

        if item.get("suggested_kql"):
            print("Suggested KQL:")
            print(f"  {item.get('suggested_kql')}")

    # Recommended Actions
    actions = incident.get("recommended_actions", [])
    print(f"\n{Fore.LIGHTCYAN_EX}== Recommended Actions =={Style.RESET_ALL}")
    for action in actions:
        print(f"{Fore.LIGHTRED_EX}  - {action}{Style.RESET_ALL}")

    # Key IOCs
    iocs = incident.get("key_iocs", [])
    print(f"\n{Fore.LIGHTCYAN_EX}== Key IOCs =={Style.RESET_ALL}")
    for ioc in iocs:
        print(f"  - {ioc}")

    print("\n" + "=" * 70 + "\n")
def display_query_context(query_context):
    print(f"{Fore.LIGHTGREEN_EX}Query context and metadata:")
    print(f"{Fore.WHITE}Table Name:   {query_context['table_name']}")
    print(f"{Fore.WHITE}Time Range:   {query_context['time_range_hours']} hour(s)")
    print(f"{Fore.WHITE}Fields:       {query_context['fields']}")
    if query_context['device_name'] != "":
        print(f"{Fore.WHITE}Device:       {query_context['device_name']}")
    if query_context['caller'] != "":
        print(f"{Fore.WHITE}Caller:       {query_context['caller']}")
    if query_context['user_principal_name'] != "":
        print(f"{Fore.WHITE}Username:     {query_context['user_principal_name']}")
    print(f"{Fore.WHITE}User Related: {query_context['about_individual_user']}")
    print(f"{Fore.WHITE}Host Related: {query_context['about_individual_host']}")
    print(f"{Fore.WHITE}NSG Related:  {query_context['about_network_security_group']}")
    print(f"{Fore.WHITE}Rationale:\n{query_context['rationale']}\n")

def display_threats(threat_list):
    count = 0
    for threat in threat_list:
        count += 1
        print(f"\n=============== Potential Threat #{count} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)  # Automatically resets to default after each print

        confidence = threat.get('confidence', '').lower()

        if confidence == 'high':
            color = Fore.LIGHTRED_EX
        elif confidence == 'medium':
            color = Fore.LIGHTYELLOW_EX
        elif confidence == 'low':
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL  # Default/no color

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get('mitre', {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get('log_lines', []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get('tags', []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")

        print("=" * 51)
    
    append_threats_to_jsonl(threat_list=threat_list)

def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    count = 0
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")
            count += 1
        print(f"{Fore.LIGHTBLUE_EX}\nLogged {count} threats to {filename}.\n")

def sanitize_literal(s: str) -> str:
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")

def sanitize_query_context(query_context):
    if 'caller' not in query_context:
        query_context['caller'] = ''
    
    if 'device_name' not in query_context:
        query_context['device_name'] = ''

    if 'user_principal_name' not in query_context:
        query_context['user_principal_name'] = ''

    if 'device_name' in query_context:
        query_context['device_name'] = sanitize_literal(query_context['device_name'])

    if 'caller' in query_context:
        query_context['caller'] = sanitize_literal(query_context['caller'])

    if "user_principal_name" in query_context:
        query_context['user_principal_name'] = sanitize_literal(query_context['user_principal_name'])

    query_context["fields"] = ', '.join(query_context["fields"])
    
    return query_context
