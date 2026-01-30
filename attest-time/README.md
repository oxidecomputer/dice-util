To get meaningful results this tool should be run through the IPCC interface as
this is the communication path that will be used on a deployed system. We do
not however enable IPCC by default due to the side effects caused by cargo
unifying features across the workspace. IPCC support must be explicitly enabled
for `attest-time` when building it: `--features ipcc`.
