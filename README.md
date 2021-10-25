# evtxIOC
- Built using python2.7

# Usage
Has to be complied in Windows environment.

```bash
pip install -r requirements.txt
```

Compile commands (to be refined)
```cmd
pyinstaller --onefile -w evtxIOC_prototypev3.py
```

Test out .exe (to be refined)
```cmd
python evtxIOC_prototypev3_sigma.py -f EfsPotato_sysmon_17_18_privesc_seimpersonate_to_system.evtx -r sysmon_efspotato_namedpipe.yml
```