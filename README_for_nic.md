python yml_to_sql.py -f evtx_samples -r rules

remove .json in rules folder when running


https://github.com/SigmaHQ/sigma

WSL - may need user to go and convert the rules first
sigmac -I -t sqlite -c config/generic/sysmon.yml -r ../rules/windows/ -o test.json

Find a way to pair the output to ruleName + description



