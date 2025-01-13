from flask import Flask, request, render_template_string
from jinja2 import Environment, FileSystemLoader
import re

app = Flask(__name__)

# Initialize Jinja environment, pointing to the directory containing the template
env = Environment(loader=FileSystemLoader('.'))

def parse_deprecated_rule(old_rule_text):
    """
    Parse relevant fields from the user-pasted, deprecated cloudflare_rate_limit.
    Returns a dict for the Jinja template. More advanced parsing may be needed in production.
    """

    # 1. Parse the 'description'
    desc_match = re.search(r'description\s*=\s*"([^"]+)"', old_rule_text)
    description = desc_match.group(1) if desc_match else "No description found"

    # to handle threshold/period references like "local.thresholds.thirty_requests"
    # and "local.times.ten_secs" by mapping them to numeric values.

    # For threshold:
    threshold_match = re.search(r'threshold\s*=\s*local\.thresholds\.(\w+)', old_rule_text)
    threshold_map = {
        'eight_requests': 8,
        'five_requests': 5,
        'three_requests': 3,
        'four_requests': 4,
        'ten_requests': 10,
        'twenty_requests': 20,
        'twelve_requests': 12,
        'thirty_requests': 30,
        'fifty_requests': 50,
        # Add more mappings as needed
    }
    if threshold_match:
        threshold_key = threshold_match.group(1)  # e.g., "thirty_requests"
        threshold = threshold_map.get(threshold_key, "[UNKNOWN]")  # Use [UNKNOWN] if not in the map
    else:
        threshold_match = re.search(r'threshold\s*=\s*(\d+)', old_rule_text)
        if threshold_match:
            threshold = int(threshold_match.group(1))  # Use the numeric value directly
        else:
            threshold = "[UNKNOWN]"

    # For period:
    period_match = re.search(r'period\s*=\s*local\.times\.(\w+)', old_rule_text)
    period_map = {
        'ten_secs': 10,
        'one_minute': 60,
        'five_minutes': 300,
        # Add more mappings as needed
    }
    if period_match:
        period_key = period_match.group(1)  # e.g., "one_minute"
        period = period_map.get(period_key, "[UNKNOWN]")  # Use [UNKNOWN] if not in the map
    else:
        # If there's no match or it's not a local.times value
        period_match = re.search(r'period\s*=\s*(\d+)', old_rule_text)
        if period_match:
            period = int(period_match.group(1))  # Use the numeric value directly
        else:
            period = "[UNKNOWN]"

    # For timeout (if needed):
    timeout_match = re.search(r'timeout\s*=\s*local\.times\.(\w+)', old_rule_text)
    timeout_map = {
        'two_minutes': 120,
        'five_minutes': 300,
        # Add more mappings as needed
    }
    if timeout_match:
        timeout_key = timeout_match.group(1)  # e.g., "two_minutes"
        mitigation_timeout = timeout_map.get(timeout_key, "[UNKNOWN]")  # Use [UNKNOWN] if not in the map
    else:
        # Parse timeout from the action block
        action_timeout_match = re.search(r'action\s*\{[^\}]*timeout\s*=\s*(\d+)', old_rule_text, re.DOTALL)
        if action_timeout_match:
            mitigation_timeout = int(action_timeout_match.group(1))  # Extract numeric timeout
        else:
            mitigation_timeout = "[UNKNOWN]"  # Default to [UNKNOWN] if not found

    # 5. Parse 'url_pattern' from lines like:
    #    url_pattern = "example.com/*test/*"
    #    If you only want the path portion, you can trim the domain part.
    # Parse url_pattern to extract full domain (host) and path
    # Extract host and path from url_pattern
    url_pattern_match = re.search(r'url_pattern\s*=\s*"([^"]+)"', old_rule_text)
    if url_pattern_match:
        original_pattern = url_pattern_match.group(1)  # e.g., "hub*.example.net/api*/test"

        # Split into host and path
        if "/" in original_pattern:
            host_part, path_part = original_pattern.split("/", 1)
        else:
            host_part, path_part = original_pattern, ""

        zone_name = ".".join(host_part.split(".")[-2:])  # e.g., "example.net"
         # Use full host for host_name
        host_name = host_part  # e.g., "api.example.net"

        # Handle host
        if "*" in host_part or ".*" in host_part:
            host_operator = "matches"
            host_pattern = re.sub(r'\*', '.*', host_part)  # Convert * to .*
        else:
            host_operator = "eq"
            host_pattern = host_part

        # Handle path
        if "*" in path_part or ".*" in path_part:
            path_pattern = re.sub(r'\*', '.*', "/" + path_part)
            path_operator = "matches"
        else:
            path_pattern = "/" + path_part
            path_operator = "eq"
    else:
        # Fallbacks if url_pattern is not found
        host_operator = "eq"
        zone_name = "example.com"
        host_name = "example.com"
        path_pattern = ".*"
        path_operator = "matches"

    # Add or replace this snippet inside your parse_deprecated_rule function
    # where you parse zone_id and host_name:

    # Extract zone_id
    zone_id_match = re.search(r'zone_id\s*=\s*var\.cloudflare_domains_map\["([^"]+)"\]', old_rule_text)
    if zone_id_match:
        # Proper domain (e.g., "example.net")
        zone_name = zone_id_match.group(1)
    else:
        # If not a proper domain, fallback to "example.com"
        zone_name = "example.com"

    # 6. Parse 'bypass_url_patterns' => single combined bypass regex
    bypass_match = re.search(r'bypass_url_patterns\s*=\s*\[([^]]+)\]', old_rule_text)
    if bypass_match:
        # Might be something like `"example.com/*test/*.*"`.
        # Extract the first item or parse them all if you like.
        bypass_str = bypass_match.group(1)
        # This is extremely naive. If you have multiple patterns, you'll need more logic.
        # We'll just grab the first pattern in the array.
        first_pattern_match = re.search(r'"([^"]+)"', bypass_str)
        if first_pattern_match:
            bypass_str_clean = first_pattern_match.group(1)
            # Convert Terraform wildcard to a regex if needed
            # e.g. "/*test/*.*" -> "/.*test/.*\..*"
            bypass_regex = re.sub(r'\*', '.*', bypass_str_clean)
        else:
            bypass_regex = ""
    else:
        bypass_regex = ""

    # 7. Parse 'methods' => e.g. methods = ["GET","POST"]
    methods_match = re.search(r'methods\s*=\s*\[([^]]+)\]', old_rule_text)
    methods_found = []
    if methods_match:
        inside = methods_match.group(1)
        # find each quoted item
        found = re.findall(r'"([^"]+)"', inside)
        methods_found = [m.upper() for m in found]

    # 8. Parse request headers from lines like:
    #      headers = [
    #        {
    #          name  = "X-Test-Header"
    #          op    = "eq"
    #          value = "my-app"
    #        },
    #        ...
    #      ]
    # You can do a naive approach to find all { ... } blocks inside headers = [...]
    # Snippet to parse a headers block within `parse_deprecated_rule`
    request_headers_block_match = re.search(
        r'headers\s*=\s*\[\s*([^\]]+)\]',  # captures everything between headers = [ ... ]
        old_rule_text,
        re.DOTALL
    )

    request_header_list = []

    if request_headers_block_match:
        headers_block = request_headers_block_match.group(1)
        # find each { ... } block
        header_entries = re.findall(r'\{\s*(.*?)\s*\}', headers_block, re.DOTALL)
        for entry in header_entries:
            # parse name, op, and value lines
            name_match = re.search(r'"name"\s*=\s*"([^"]+)"', entry)
            op_match = re.search(r'"op"\s*=\s*"([^"]+)"', entry)
            value_match = re.search(r'"value"\s*=\s*"([^"]+)"', entry)
            if name_match and op_match and value_match and name_match.group(1).lower() != 'cf-cache-status':
                request_header_list.append({
                    "name": name_match.group(1),
                    "op": op_match.group(1),
                    "value": value_match.group(1),
                })

    # 9. Parse response headers similarly
    response_header_list = []
    response_headers_block_match = re.search(
        r'response\s*\{\s*headers\s*=\s*\[\s*([^\]]+)\]', old_rule_text, re.DOTALL
    )
    if response_headers_block_match:
        headers_block = response_headers_block_match.group(1)
        header_entries = re.findall(r'\{\s*(.*?)\s*\}', headers_block, re.DOTALL)
        for entry in header_entries:
            name_match  = re.search(r'name\s*=\s*"([^"]+)"', entry)
            op_match    = re.search(r'op\s*=\s*"([^"]+)"', entry)
            value_match = re.search(r'value\s*=\s*"([^"]+)"', entry)
            if name_match and op_match and value_match:
                response_header_list.append({
                    "name":  name_match.group(1),
                    "op":    op_match.group(1),
                    "value": value_match.group(1),
                })

    # 10. Parse statuses from lines like `statuses = [301, 404]` => counting_expression
    # Initialize an empty list to hold parts of the counting expression
    counting_expression_parts = []

    # Parse statuses (e.g., http.response.code in { 301 404 })
    statuses_match = re.search(r'statuses\s*=\s*\[([^]]+)\]', old_rule_text)
    if statuses_match:
        statuses_str = statuses_match.group(1).strip()
        statuses = re.findall(r'\d+', statuses_str)
        if statuses:
            counting_expression_parts.append(f"(http.response.code in {{ {' '.join(statuses)} }})")

    # Parse response headers for counting_expression
    response_headers_block_match = re.search(
        r'"name"\s*=\s*"Cf-Cache-Status".*?"op"\s*=\s*"([^"]+)".*?"value"\s*=\s*"([^"]+)"',
        old_rule_text,
        re.DOTALL
    )

    if response_headers_block_match:
        op = response_headers_block_match.group(1)
        value = response_headers_block_match.group(2).lower()  # Ensure case-insensitivity
        if op == "eq":
            counting_expression_parts.append(
                f"not (any(http.response.headers[\"cf-cache-status\"][*] == \"{value}\") or "
                f"any(http.response.headers[\"cf-cache-status\"][*] == \"{value.upper()}\"))"
            )
        elif op == "ne":
            counting_expression_parts.append(
                f"(any(http.response.headers[\"cf-cache-status\"][*] != \"{value}\") and "
                f"any(http.response.headers[\"cf-cache-status\"][*] != \"{value.upper()}\"))"
            )

    # Combine all parts of the counting expression
    if counting_expression_parts:
        counting_expression = " and ".join(counting_expression_parts)
    else:
        counting_expression = ""

    # Build our final data dictionary for the Jinja template
    data = {
        "new_resource_name":  "auto_migrated_ruleset",
        "new_description":    None,
        "new_name":           None,
        "host_name":          host_name,
        "zone_name":          zone_name,
        "zone_id":            "placeholder_zone", # parse or keep static if needed
        "description":        description,
        "threshold":          threshold,
        "period":             period,
        "mitigation_timeout": mitigation_timeout,
        "counting_expression": counting_expression,
        "host_operator":        host_operator,  # eq or matches
        "host_pattern":         host_pattern,  # e.g., "hub*.example.net"
        "path_pattern":         path_pattern,  # e.g., "/api.*/test"
        "path_operator":        path_operator,  # eq or matches
        "methods":            methods_found,
        "bypass_regex":       bypass_regex,
        "request_headers":    request_header_list,
        "response_headers":   response_header_list,
    }

    return data


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # User has submitted the form with old rule text
        old_rule_text = request.form.get('deprecated_rule', '')

        # Parse user input
        parsed_data = parse_deprecated_rule(old_rule_text)

        # Render using the Jinja template
        template = env.get_template('template.j2')
        rendered = template.render(rules_data=[parsed_data])

        # Show the migrated rule
        return render_template_string("""
        <!doctype html>
        <html>
        <head>
            <title>Migrated Rule</title> 
            <style>
                textarea {
                    width: 100%;
                    height: 300px;
                    font-family: monospace;
                    font-size: 14px;
                }
                button {
                    margin-top: 10px;
                    padding: 10px 20px;
                    font-size: 14px;
                    cursor: pointer;
                }
            </style>
            <script>
                function copyToClipboard() {
                    const textArea = document.getElementById("convertedRule");
                    textArea.select();
                    textArea.setSelectionRange(0, 99999); // For mobile devices
                    document.execCommand("copy");
                    alert("Copied to clipboard!");
                }
            </script>
        </head>
        <body>
            <a href="/"><h1>Migrated Rule</a> - <a href="https://emreovunc.com">@EmreOvunc</a></h1>
            <textarea id="convertedRule" readonly>{{ migrated_rule }}</textarea>
            <br>
            <button onclick="copyToClipboard()">Copy to Clipboard</button>
            <br><br>
            <a href="/">Back to Form</a>
        </body>
        </html>
        """, migrated_rule=rendered)

    # GET request => Show form to paste the old rule
    return render_template_string("""
    <!doctype html>
    <html>
      <head><title>Cloudflare Rule Migrator</title></head>
      <body>
        <a href="/"><h1>Cloudflare Rule Migrator</a> - <a href="https://emreovunc.com">@EmreOvunc</a></h1>
        <form method="POST">
          <p>Paste your deprecated <code>cloudflare_rate_limit</code> rule here:</p>
          <textarea name="deprecated_rule" rows="20" cols="80"></textarea>
          <br><br>
          <input type="submit" value="Convert Rule"/>
        </form>
      </body>
    </html>
    """)

if __name__ == "__main__":
    app.run(debug=True)
