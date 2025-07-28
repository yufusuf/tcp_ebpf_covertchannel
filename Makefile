.PHONY: manager 


sender: bpf_sender.c
	clang -O2 -g -Wall -target bpf -c bpf_sender.c -o bpf_sender.o
manager:
	$(MAKE) -C manager
	cp -f manager/bpf_map_manager .
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
	# sudo ip netns exec insec socat -u -b 32768 /dev/urandom TCP:10.0.0.1:1234,tcp-nodelay
	sudo ip netns exec insec bash -c 'pv -q -L 100k /dev/urandom | socat -u - TCP:10.0.0.1:1234,tcp-nodelay'
run_dummy_server:
	sudo ip netns exec sec socat -u TCP-LISTEN:1234,bind=10.0.0.1,reuseaddr /dev/null
receiver: receiver.c
	gcc receiver.c -o receiver -Wall -O2 -lpcap -lpthread
run_receiver:
	sudo ip netns exec insec ./receiver

