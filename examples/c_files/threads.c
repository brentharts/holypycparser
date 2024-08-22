// cpu core
`1
// thread id
`0
// registers
`a0,a1,a2,a3,a4,a5,a6,a8
`U0 ThreadA() {
	U8 a = 0;
	U8 c = 10;
	while (1){
		PUTPIXEL(0,0+a, c);
		PUTPIXEL(1,1+a, c);
		PUTPIXEL(2,2+a, c);
		PUTPIXEL(3,3+a, c);
		c++;
	}
}

`1`1`s0,s1,s2,s3,s4,s5,s6,s8`U0 ThreadB() {
	U8 B = 10;
	U8 c = 0;
	while (1){
		PUTPIXEL(B+10,B, c);
		B ++;
		c ++;
	}
}