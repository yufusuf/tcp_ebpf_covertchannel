compile: bpf_sender.c
	clang -O2 -g -Wall -target bpf -c bpf_sender.c -o bpf_sender.o
# compile_loader:
# 	clang -O2 -Wall -o bpf_loader bpf_loader.c -lbpf
# gen_skel:
# 	bpftool gen skeleton bpf_sender.o > bpf_sender.skel.h
clean:
	rm -f bpf_sender.o
load:
	sudo ip netns exec sec tc filter add dev veth_sec egress bpf da obj bpf_sender.o verbose
unload:
	sudo ip netns exec sec tc filter del dev veth_sec egress
run_dummy_sender:
	# sudo ip netns exec insec socat -v -d STDIN TCP:10.0.0.1:1234
	sudo ip netns exec insec socat -u -b 32768 /dev/urandom TCP:10.0.0.1:1234,tcp-nodelay
run_dummy_server:
	sudo ip netns exec sec socat -u TCP-LISTEN:1234,bind=10.0.0.1,reuseaddr /dev/null
receiver: receiver.c
	gcc receiver.c -o receiver -Wall -O2 -lpcap
run_receiver:
	sudo ip netns exec insec ./receiver

