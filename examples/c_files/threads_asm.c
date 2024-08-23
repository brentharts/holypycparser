// thread id
`0
// registers
`a0,a1,a2,a3,a4,a5,a6,a8
`U0 ThreadA() {
	while (1){
		__asm__ (
			"addi gp, gp, 1"
		);
	}
}

`1`s0,s1,s2,s3,s4,s5,s6,s8`U0 ThreadB() {
	while (1){
		__asm__ (
			"addi gp, gp, 1"
		);
	}
}