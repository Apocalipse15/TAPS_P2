import json
import geoip2.database

DB_PATH = r'.\GeoLite2-Country.mmdb'

# Assume-se q ele n pode ter como guard alguem q pertence à aliança dele ou a sí mesmo
def guard_security(client_loc, guards, alliances, total_weight, sum_weight):
    # Calculate security score for guard set
    # Base on client location and adversary model
    poss_guards = []
    for guard in guards:
        country_of_guard, _ = get_country(guard["ip"])
        if get_country(guard["ip"])[0] == client_loc:
            continue
        trust_score = 1.0
        for alliance in alliances:
            if country_of_guard in alliance.get("countries", []):
                if client_loc in alliance.get("countries", []):
                    trust_score = 0.0
                    break
                trust_score = min(alliance.get("trust", 0.0), trust_score)

        if trust_score <= 0.0:
            continue

        poss_guards.append({"IP": guard["ip"], "trust": trust_score, "weight": guard.get("bandwidth", {}).get("measured", 0) / total_weight, "family": guard.get("family", []), "fingerprint": guard.get("fingerprint", ""), "country": country_of_guard})

    return poss_guards

def get_exit_candidates(nodes, dest, alliances, total_weight):
    poss_exits = []

    for node in nodes:
        if "reject {dest}" in node["exit"]: # or "reject *:*" in node["exit"]:
            continue;
        country_of_node, _ = get_country(node["ip"])
        if get_country(node["ip"])[0] == get_country(dest)[0]:
            continue
        trust_score = 1.0
        for alliance in alliances:
            if country_of_node in alliance.get("countries", []):
                if get_country(dest)[0] in alliance.get("countries", []):
                    #trust_score = max(0.0, trust_score)
                    continue
                trust_score = min(alliance.get("trust", 0.0), trust_score)

        if trust_score <= 0.0:
            continue
        
        poss_exits.append({"IP": node["ip"], "trust": trust_score, "weight": node.get("bandwidth", {}).get("measured", 0) / total_weight, "family": node.get("family", []), "fingerprint": node.get("fingerprint", ""), "country": country_of_node})

    return poss_exits

def check_if_same_country_or_alliance(node1, node2, alliances):
    country1 = node1.get("country")
    country2 = node2.get("country")
    
    if country1 == country2:
        return True
    
    for alliance in alliances:
        if country1 in alliance.get("countries", []) and country2 in alliance.get("countries", []):
            return True
    
    return False

def select_path(poss_guards, poss_exists, alpha_params, alliances):
    GUARD_PARAMS = {         
        "safe_upper": 0.95 ,         
        "safe_lower": 2.0 ,         
        "accept_upper": 0.5 ,         
        "accept_lower": 5.0 ,        
        "bandwidth_frac": 0.2
    }

    EXIT_PARAMS = {
        "safe_upper": 0.95 ,         
        "safe_lower": 2.0 ,         
        "accept_upper": 0.1 ,         
        "accept_lower": 10.0 ,        
        "bandwidth_frac": 0.2
    }
    
    # Sort relays by descending trust score
    # Separate into safe / acceptable categories ( recommended
    # values above )
    # Select until Bandwidth threshold reached .
    # Return bandwidth - weighted choice .

    # Guards part

    poss_guards.sort(key=lambda x: x["trust"], reverse=True)

    max_trust_score = poss_guards[0]["trust"] if poss_guards else 0

    relays_size = len(poss_guards)
    
    print(f"Max trust score: {max_trust_score}")
    print(f"Relays size: {relays_size}")

    safe_guards = []
    acceptable_guards = []
    w_guards = 0
    i_guards = 0

    while i_guards < relays_size and poss_guards[i_guards]["trust"] >= GUARD_PARAMS["safe_upper"] * max_trust_score and 1- poss_guards[i_guards]["trust"] <= GUARD_PARAMS["safe_lower"] * (1 - max_trust_score) and w_guards < GUARD_PARAMS["bandwidth_frac"]:
        safe_guards.append(poss_guards[i_guards])
        w_guards += poss_guards[i_guards]["weight"]
        i_guards += 1

    while i_guards < relays_size and poss_guards[i_guards]["trust"] >= GUARD_PARAMS["accept_upper"] * max_trust_score and 1- poss_guards[i_guards]["trust"] <= GUARD_PARAMS["accept_lower"] * (1 - max_trust_score) and w_guards < GUARD_PARAMS["bandwidth_frac"]:
        acceptable_guards.append(poss_guards[i_guards])
        w_guards += poss_guards[i_guards]["weight"]
        i_guards += 1

    # Exits part

    poss_exists.sort(key=lambda x: x["trust"], reverse=True)

    max_trust_score = poss_exists[0]["trust"] if poss_exists else 0

    relays_size = len(poss_exists)
    
    safe_exits = []
    acceptable_exits = []
    w_guards = 0
    i_guards = 0

    while i_guards < relays_size and poss_exists[i_guards]["trust"] >= EXIT_PARAMS["safe_upper"] * max_trust_score and 1- poss_exists[i_guards]["trust"] <= EXIT_PARAMS["safe_lower"] * (1 - max_trust_score) and w_guards < EXIT_PARAMS["bandwidth_frac"]:
        safe_exits.append(poss_exists[i_guards])
        w_guards += poss_exists[i_guards]["weight"]
        i_guards += 1

    while i_guards < relays_size and poss_exists[i_guards]["trust"] >= EXIT_PARAMS["accept_upper"] * max_trust_score and 1- poss_exists[i_guards]["trust"] <= EXIT_PARAMS["accept_lower"] * (1 - max_trust_score) and w_guards < EXIT_PARAMS["bandwidth_frac"]:
        acceptable_exits.append(poss_exists[i_guards])
        w_guards += poss_exists[i_guards]["weight"]
        i_guards += 1


    # Prints about the guards and exits

    print(f"Safe Guards ({len(safe_guards)}):")

    #for guard in safe_guards:
    #    print(f"  IP: {guard['IP']}, Trust: {guard['trust']:.2f}, Weight: {guard['weight']:.2f}, Fingerprint: {guard['fingerprint']}")

    print(f"\nAcceptable Guards ({len(acceptable_guards)}):")
    #for guard in acceptable_guards:
    #    print(f"  IP: {guard['IP']}, Trust: {guard['trust']:.2f}, Weight: {guard['weight']:.2f}, Fingerprint: {guard['fingerprint']}")
    
    print(f"\nSafe Exits ({len(safe_exits)}):")
    #for exit in safe_exits:
    #    print(f"  IP: {exit['IP']}, Trust: {exit['trust']:.2f}, Weight: {exit['weight']:.2f}, Fingerprint: {exit['fingerprint']}")

    print(f"\nAcceptable Exits ({len(acceptable_exits)}):")
    #for exit in acceptable_exits:
    #    print(f"  IP: {exit['IP']}, Trust: {exit['trust']:.2f}, Weight: {exit['weight']:.2f}, Fingerprint: {exit['fingerprint']}")

    # Select the best guard and exit from the safe sets (note: guards and exits can be apart of the same family, fingerprint, or ASN)

    relays = []
    for guard in safe_guards:
        for exit in safe_exits:
            # Check if they belong in the same family
            if guard["fingerprint"] in exit.get("family", []) or exit["fingerprint"] in guard.get("family", []) or guard["fingerprint"] == exit["fingerprint"] or guard["fingerprint"] in exit["family"] or exit["fingerprint"] in guard.get("family", []) or check_if_same_country_or_alliance(guard, exit, alliances):
                continue
            relays.append({
                "guard": guard,
                "exit": exit,
                "trust": min(guard["trust"], exit["trust"]),
                "bandwidth": min(guard["weight"], exit["weight"])
            })

    if len(relays) > 0:
        relays.sort(key=lambda x: (x["trust"], x["bandwidth"]), reverse=True)
        print(f"\nFound top relay from the safe sets")
        return relays[0]

    for guard in safe_guards:
        for exit in acceptable_exits:
            # Check if they belong in the same family
            if guard["fingerprint"] in exit.get("family", []) or exit["fingerprint"] in guard.get("family", []) or guard["fingerprint"] == exit["fingerprint"] or guard["fingerprint"] in exit["family"] or exit["fingerprint"] in guard.get("family", []) or check_if_same_country_or_alliance(guard, exit, alliances):
                continue
            relays.append({
                "guard": guard,
                "exit": exit,
                "trust": min(guard["trust"], exit["trust"]),
                "bandwidth": min(guard["weight"], exit["weight"])
            })

    for guard in acceptable_guards:
        for exit in safe_exits:
            # Check if they belong in the same family
            if guard["fingerprint"] in exit.get("family", []) or exit["fingerprint"] in guard.get("family", []) or guard["fingerprint"] == exit["fingerprint"] or guard["fingerprint"] in exit["family"] or exit["fingerprint"] in guard.get("family", []) or check_if_same_country_or_alliance(guard, exit, alliances):
                continue
            relays.append({
                "guard": guard,
                "exit": exit,
                "trust": min(guard["trust"], exit["trust"]),
                "bandwidth": min(guard["weight"], exit["weight"])
            })
        for exit in acceptable_exits:
            # Check if they belong in the same family
            if guard["fingerprint"] in exit.get("family", []) or exit["fingerprint"] in guard.get("family", []) or guard["fingerprint"] == exit["fingerprint"] or guard["fingerprint"] in exit["family"] or exit["fingerprint"] in guard.get("family", []) or check_if_same_country_or_alliance(guard, exit, alliances):
                continue
            relays.append({
                "guard": guard,
                "exit": exit,
                "trust": min(guard["trust"], exit["trust"]),
                "bandwidth": min(guard["weight"], exit["weight"])
            })

    relays.sort(key=lambda x: (x["trust"], x["bandwidth"]), reverse=True)

    print(f"\nTotal Circuits Found: {len(relays)}")

    return relays[0] if relays else None

def get_middle_node(relays, top_relay):
    relays.sort(key=lambda x: (x["bandwidth"].get("measured", 0)), reverse=True)
    for relay in relays:
        if relay["fingerprint"] != top_relay["guard"]["fingerprint"] and relay["fingerprint"] != top_relay["exit"]["fingerprint"] and relay["fingerprint"] not in top_relay["guard"].get("family", []) and relay["fingerprint"] not in top_relay["exit"].get("family", []):
            return {
                "guard": top_relay["guard"],
                "exit": top_relay["exit"],
                "middle": relay
            }
    
    return None

def get_country(ip_address):
    try:
        with geoip2.database.Reader(DB_PATH) as reader:
            response = reader.country(ip_address)
            return response.country.iso_code, response.country.name
    except Exception as e:
        print(f"Error looking up IP: {e}")
        return None, None

# THIS IS MAIN 

sum_weight = 0.0

json_file_path = 'tor_consensus.json'

with open(json_file_path, 'r') as file:
    data = json.load(file)

if isinstance(data, list):
    nodes_list = data
else:
    raise ValueError("Expected a list of objects at the root of the JSON file")

#for obj in nodes_list:
#    print("Fingerprint:", obj.get("fingerprint"))
#    print("Nickname:", obj.get("nickname"))
#    print("IP:", obj.get("ip"))
#    print("Port:", obj.get("port"))
#    print("Bandwidth:", obj.get("bandwidth"))
#    print("Family:", obj.get("family"))
#    print("AS Number:", obj.get("asn"))
#    print("Exit Policy:", obj.get("exit"))
#    print("-" * 40)

for obj in nodes_list:
    if get_country(obj["ip"])[0] is None:
        print(f"Warning: Could not find country for IP {obj['ip']}. Skipping this node.")
        nodes_list.remove(obj)
        continue

# Path to your JSON file
json_file_path = 'Project2ClientInput.json'

# Load JSON data
with open(json_file_path, 'r') as file:
    data = json.load(file)

# Extract relevant parts
alliances = data.get("Alliances", [])
client = data.get("Client")
destination = data.get("Destination")

# Print all data
print(f"Client IP: {client}")
print(f"Destination IP: {destination}")
print("\nAlliances:")

for i, alliance in enumerate(alliances, start=1):
    countries = alliance.get("countries", [])
    trust = alliance.get("trust")
    print(f"Alliance {i}:")
    print(f"Countries: {', '.join(countries)}")
    print(f"Trust: {trust}")

codeC, nameC = get_country(client)
codeD, nameD = get_country(destination)

print(f"\nClient Country Code: {codeC}, Name: {nameC}")
print(f"Destination Country Code: {codeD}, Name: {nameD}")

# Get total weight of all nodes
total_weight = sum(node.get("bandwidth", {}).get("measured", 0) for node in nodes_list)

print(f"\nTotal Bandwidth Weight: {total_weight}")

guards = guard_security(client, nodes_list, alliances, total_weight, sum_weight)

print(f"\nPossible Guards ({len(guards)}):")

if len(guards) == 0:
    print("No suitable guards found. This means no valid path exists.")
    # For now, just exit
    exit()

exit_candidates = get_exit_candidates(nodes_list, destination, alliances, total_weight)
print(f"\nPossible Exits ({len(exit_candidates)}):")

if len(exit_candidates) == 0:
    print("No suitable exits found. This means no valid path exists.")
    # For now, just exit
    exit()

select_path = select_path(guards, exit_candidates, {}, alliances)

if select_path == None:
    print("No suitable path found (guards and exits part).")
    # For now, just exit
    exit()

print(f"\nSelected Path: {select_path}")

final_path = get_middle_node(nodes_list, select_path)

if final_path == None:
    print("No suitable path found. (Middle node part)")
    # For now, just exit
    exit()

print("\nFinal Path:\n")


guard = [node for node in nodes_list if node['fingerprint'] == final_path['guard']['fingerprint']]
middle = final_path['middle']
exit = [node for node in nodes_list if node['fingerprint'] == final_path['exit']['fingerprint']]

print(f"\nGuard: {guard[0]['ip']}, with bandwidth: {guard[0]["bandwidth"].get("measured", 0)} \nExit: {exit[0]['ip']}, with bandwidth: {exit[0]["bandwidth"].get("measured", 0)} \nMiddle: {middle['ip']}, with bandwidth: {middle['bandwidth'].get("measured", 0)}")


circuit = guard, middle, exit  # These should be full dicts

# Path to the output file
output_path = "circuit.json"

# Save to file
with open(output_path, "w", encoding="utf-8") as f:
    json.dump(circuit, f, ensure_ascii=False, indent=2)