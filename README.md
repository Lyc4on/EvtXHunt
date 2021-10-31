# evtxIOC
- Built using python2.7

# Usage
Has to be complied in Windows environment.

```bash
pip install -r requirements.txt
```

Compile into exe (to be refined)
```cmd
pyinstaller evtxIOC_prototypev5_sigma.py -F --hidden-import="pyevtx" --hidden-import="yaml" --hidden-import="sqlalchemy.sql.default_comparator"
```

Run python script (to be refined)
```cmd
python evtxIOC_prototypev5_sigma.py -f evtx_samples -r rules\\rules_windows_generic.json -o temp\\sub
```

Run exe (to be refined)
```cmd
evtxIOC_prototypev5_sigma.exe -f evtx_samples -r rules\\rules_windows_generic.json -o temp\\sub
```
