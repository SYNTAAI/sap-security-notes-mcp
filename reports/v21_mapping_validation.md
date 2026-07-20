# v2.1 Mapping Validation Report

Cross-checks `data/component_mapping.yaml`'s curated app-component -> software-component inferences against what SAP actually publishes in each note's `affected[]` list. **This report does not edit the YAML** -- changes wait for human sign-off, same gate as the original v2 mapping.

## DMIS

Curated prefixes: `CA-LT, CA-DT-ANA` (excluded: `-`)

- Confirmed: 2
- Contradicted: 0
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3723097 (CA-LT-PCL)
- 3697979 (CA-DT-ANA)

## S4CORE

Curated prefixes: `FI, FIN-FSCM, SD, PM, MM, CA-JVA, CA-EPT, CA-DMS, IS-U, PPM` (excluded: `-`)

- Confirmed: 13
- Contradicted: 3
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3713902 (FI-FIO-AP-PAY)
- 3537373 (PPM-PRO)
- 3515598 (FIN-FSCM-CLM-COP)
- 3718083 (SD-MD-CM)
- 3731908 (CA-JVA-JVA)
- 3715177 (PM-EQM-RS)
- 3715097 (PM-EQM-EQ)
- 3711682 (PM-EQM-RS)
- 3703813 (IS-U-TO-MI)
- 3530544 (FI-FIO-GL-TRA)
- 3678417 (CA-DMS-OP)
- 3215823 (MM-PUR-SVC-SES)
- 3122486 (FI-LOC-FI-RU)

**Contradicted** (published affected[] does NOT include S4CORE for this note -- review):
- 3751691 (CA-EPT-SSC) -- published: S4FND
- 3716767 (PM-EQM-RS) -- published: UIS4H
- 3646297 (FI-FIO-AP-PAY) -- published: UIAPFI70, UIS4H

## S4FND

Curated prefixes: `CA-WUI` (excluded: `-`)

- Confirmed: 1
- Contradicted: 0
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3155685 (CA-WUI-UI)

## SAP_BASIS

Curated prefixes: `BC` (excluded: `BC-JAS, BC-XS, BC-CP, BC-WD-JAV, BC-INS-CTC, BC-MID-CON-JCO, BC-PIN, BC-SRV-FP, BC-FES-GXT, BC-BW`)

- Confirmed: 16
- Contradicted: 7
- No page evidence: 1

**Confirmed** (mapping agrees with published data):
- 3754659 (BC-BSP)
- 3746332 (BC-SEC-LGN-SML)
- 3735546 (BC-DWB-DIC-AC)
- 3692004 (BC-FES-ITS)
- 3735359 (BC-MID-ICF)
- 3730019 (BC-ABA-SC)
- 3728690 (BC-BSP)
- 3724838 (BC-EIM-ESH)
- 3704740 (BC-DB-SDB)
- 3703856 (BC-DB-ORA-CCM)
- 3694383 (BC-DB-INF)
- 3689080 (BC-TWB-TST-ECA)
- 3710111 (BC-BMT-WFM)
- 3697567 (BC-SEC-WSS)
- 3672622 (BC-DWB-CEX-CF)
- 3396109 (BC-FES-BUS)

**Contradicted** (published affected[] does NOT include SAP_BASIS for this note -- review):
- 3773304 (BC-CTS-TMS-PLS) -- published: CTS_UPLOAD_CLT
- 3692165 (BC-CST-NI) -- published: KRNL64NUC, KRNL64UC, SAP_ROUTER, KERNEL
- 3717897 (BC-MID-RFC) -- published: KRNL64NUC, KRNL64UC, KERNEL
- 3665042 (BC-WD-UR) -- published: SAP_UI
- 3678313 (BC-CST-IC) -- published: KRNL64NUC, KRNL64UC, KERNEL
- 3674774 (BC-MID-RFC) -- published: KRNL64NUC, KRNL64UC, KERNEL
- 3503138 (BC-FES-WGU) -- published: KRNL64UC, KERNEL

**No page evidence either way:**
- 3747367 (BC-FES-ITS)

## SAP_BW

Curated prefixes: `BC-BW` (excluded: `-`)

- Confirmed: 2
- Contradicted: 0
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3748819 (BC-BW-ODP)
- 3703385 (BC-BW)

## SAP_GWFND

Curated prefixes: `OPU-GW` (excluded: `-`)

- Confirmed: 1
- Contradicted: 0
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3433366 (OPU-GW-V4)

## SAP_HR

Curated prefixes: `PA, PY` (excluded: `-`)

- Confirmed: 0
- Contradicted: 3
- No page evidence: 0

**Contradicted** (published affected[] does NOT include SAP_HR for this note -- review):
- 3705094 (PA-OS) -- published: S4HCMRXX, SAP_HRRXX
- 3680767 (PA-PA-XX) -- published: S4HCMRXX, SAP_HRRXX
- 3701020 (PY-PT) -- published: S4HCMCPT, SAP_HRCPT

## SAP_UI

Curated prefixes: `CA-FLP, HAN-AS-INA-UI` (excluded: `-`)

- Confirmed: 1
- Contradicted: 1
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3682699 (CA-FLP-FE-COR)

**Contradicted** (published affected[] does NOT include SAP_UI for this note -- review):
- 3726583 (HAN-AS-INA-UI) -- published: SAPUI5

## ST-PI

Curated prefixes: `SV-SMG-SDD` (excluded: `-`)

- Confirmed: 4
- Contradicted: 0
- No page evidence: 0

**Confirmed** (mapping agrees with published data):
- 3707930 (SV-SMG-SDD)
- 3705882 (SV-SMG-SDD)
- 3691645 (SV-SMG-SDD)
- 3680416 (SV-SMG-SDD)

## Mapping entries with zero page evidence

- **SAP_HR** -- predicted notes exist but none publish this exact software component name

## Summary

- Total confirmed: 40
- Total contradicted: 14
- Total no page evidence: 1
