iptables -I FORWARD 1 -m string --string "BitTorrent" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "BitTorrent protocol" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "peer_id=" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string ".torrent" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "announce.php?passkey=" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "torrent" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "announce" --algo bm --to 65535 -j DROP
iptables -I FORWARD 1 -m string --string "info_hash" --algo bm --to 65535 -j DROP
