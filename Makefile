KERNEL_VERSION := $(shell uname -r)
BPF_INCLUDES := -I/usr/lib/modules/$(KERNEL_VERSION)/build/include \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/arch/x86/include/generated \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/arch/x86/include \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build/include/linux \
                -I/usr/lib/modules/$(KERNEL_VERSION)/build
TARGET := bpfel
GOPACKAGE := tracing_service
OUTPUT_DIR := ./pkg/${GOPACKAGE}
OUTPUT_STEM := packet_logging_bpf
BPF_SOURCE := tracing.bpf.c

all: bpf build

bpf:
	GOPACKAGE=$(GOPACKAGE) go run github.com/cilium/ebpf/cmd/bpf2go -output-dir ${OUTPUT_DIR} -output-stem "${OUTPUT_STEM}" -type execve_event -type connect_event -type destroy_connection_event -type tcp_retransmission_event -type tcp_retransmission_synack_event -type packet_drop_event -type file_open_event -target "${TARGET}" bpf "${BPF_SOURCE}" -- $(BPF_INCLUDES)
	sed --in-place --regexp-extended -e 's/loadBpf\(/LoadBpf(/g' -e 's/loadBpfObjects\(/LoadBpfObjects(/g' -e 's/(bpf(Objects|Programs|Maps|Specs|ProgramSpecs|MapSpecs|Variables|VariableSpecs))\b/Bpf\2/g' -e 's/^(type|func) ([a-z])/\1 \U\2\E/g' ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.go

build:
	go build

clean:
	rm -f ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.go ${OUTPUT_DIR}/${OUTPUT_STEM}_${TARGET}.o

.PHONY: bpf build clean
