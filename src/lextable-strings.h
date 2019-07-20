/* set of parsable strings -- ALL LOWER CASE */

#if 1
static const char *set[] = {
		"get ",//0
			"post ",//1
			"options ",//2

			"host:",//3
			"connection:",//4
			"upgrade:",//5
			"origin:",//6

			"sec-websocket-draft:",//7
			"\x0d\x0a",//8
			"sec-websocket-extensions:",//9
			"sec-websocket-key1:",//10
			"sec-websocket-key2:",//11
			"sec-websocket-protocol:",//12

			"sec-websocket-accept:",//13
			"sec-websocket-nonce:",//14

			"http/1.1 ",//15
			"http2-settings:",//16
			"accept:",//17
			"access-control-request-headers:",//18

			"if-modified-since:",//19
			"if-none-match:",//20
			"accept-encoding:",//21
			"accept-language:",//22

			"pragma:",//23
			"cookie:",//24
			"content-length:",//25
			"content-type:",//26
			"sec-websocket-key:",//27
			"sec-websocket-version:",//28
			"sec-websocket-origin:",//29


			"user-agent:",//30
			"x-ufsrvcid:",//31
			"x-cm-token:",//32
			"x-forwarded-for:",//33

			"uri-args", //34/* fake header used for uri-only storage */

			"", //35/* not matchable */

};
#endif
