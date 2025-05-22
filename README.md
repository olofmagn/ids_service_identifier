# IDS Service Name Searcher
 This tool helps analysts quickly identify rules related to a particular service (e.g., `Apache Kylin, MySQL`) by
scanning the `msg` field in alert definitions in rule sets for intrusion detection systems like Suricata and Snort.

## 🔍 What It Does
- Searches for specific service names (e.g., `Apache Kylin`) by scanning the `msg` field of Suricata rules.
- Extracts and saves matched result to file to directly use in a pipeline like github.
- Supports filtering rules based on user-defined criteria.
- Efficent input & output handling using `argparser`.
- Efficent iteration and processing of large datasets.

## 🧠 How It Works
```python

def _find_matches(self, chunk: List[str], output_file: Optional[TextIO] = None) -> int:
    if not self.service_name:
        return 0

    matched_lines = 0
    service_name_lower = self.service_name.lower()

    for line in chunk:
        match = self.service_pattern.search(line)
        if not match:
            continue

        msg_content = match.group(1)
        if not msg_content or service_name_lower not in msg_content.lower():
            continue

        matched_lines += 1

        if output_file:
            output_file.write(line)
        else:
            self.logger.info(line.rstrip())

    return matched_lines
```

## 📂 File structure
- servicename_finder.py
- README.md
- emerging-all.rules.txt
- inventorylist.pdf

## ✅ Requirements
- Python 3.7+
- No external dependencies

## 📌 Notes
- This tool is used to quickly identify rules related to a inventory list.
- It is under continous development as more features are about to be added.

## 📦 Usage

1. Clone the repository on your local machine:

```
git clone https://github.com/olofmagn/ids_service_identifier.git
```

2. Run the script with 10 threads:

```python
python3 servicename_finder.py -i emerging-all.rules.txt -o test2.txt -s "Apache Struts" -t 10
```

3. Extract and saves matched result to file to directly use in a pipeline (CI/CD).

