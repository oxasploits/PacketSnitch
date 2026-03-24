cd /tmp
rm /tmp/testcases -rf

/usr/lib/packetsnitch/resources/backend/snitch "/home/mwhittaker/Hacks/projects/packetsnitch/Samples/hustoj_capture.pcapng" -a -o /tmp/testcases
