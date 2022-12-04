
default: all

all: proofs/secure_boot_analyzed.spthy proofs/hardware_attestation_analyzed.spthy

proofs/secure_boot_analyzed.spthy: secure_boot.spthy 
	tamarin-prover --prove secure_boot.spthy -O=proofs > proofs/secure_boot_summary.txt

proofs/hardware_attestation_analyzed.spthy: hardware_attestation.spthy hardware_attestation_oracle.py
	tamarin-prover --prove hardware_attestation.spthy -O=proofs > proofs/hardware_attestation_summary.txt
