#include "Parser.h"
Parser::Parser(){}

void Parser::lexicalAnalysis(const string expr){

	// step 1, create words mask
	string mask, buffer;
	int flag = 0;		// mark that character is not space ' '
	for(int i = 0; i < expr.length(); i++){
		if(expr[i] != ' ' && flag == 0){
			flag = 1;
		}
		if(expr[i] == ' '){
			flag = 0;
		}
		mask += (char) (flag + 48);
	}	

	// step 2, parsing tokens
	flag = 0;
	for(int i = 0; i < expr.length(); i++){
		if(mask[i] == '1'){  // character not space only
			buffer += expr[i];
			flag = 1;
			if(i == expr.length() - 1)
				tokens.push(buffer);
		}
		else if(flag == 1){
			tokens.push(buffer);
			buffer = "";
			flag = 0;
		}
	}
	convertToPostfix();
}

int Parser::isField(string token){
	string fields[22] = {"ver", "iphdrlen", "tos", "ttlen", "ttl", "proto", "ipsrc", "ipdst", "sport", "dport", "seqno", "ackno", "tcphdrlen", "urgflag", "ackflag", "pshflag", "rstflag", "synflag", "finflag", "windowsiz", "urgpnt", "udplen"};
	for(int i = 0; i < 22; i++)
		if(token == fields[i]){
			return 1;
	}
	return -1;
}

int Parser::getPriority(string op){
	if( op == "&&" || op == "||" )
		return 1;
	else if( op == "!=" || op == "==" || op == ">" || op == ">=" || op == "<" || op == "<=")
		return 2;
	else return -1;
}

int Parser::isOperator(string op){
	if(getPriority(op) == -1){
		if( op != "(" && op != ")") return -1;
		else return -2;
	}
	return 1;
}

void Parser::convertToPostfix(){
	stack<string> Stack;
	string token;
	while(!tokens.empty()){
		token = tokens.front();
		// kiem tra co phai toan tu hay khong
		if(isOperator(token) == 1){
			if(!Stack.empty()){
				string topStack = Stack.top();
				if(getPriority(topStack) > getPriority(token)){
					postFix.push(topStack);
					Stack.pop();
				}
				Stack.push(token);
			}
			else{
				Stack.push(token);
			}
		}
		else{
			if(token == "(")
				Stack.push(token);
			else if(token == ")"){
				string topStack;
				while((topStack = Stack.top()) != "("){
					postFix.push(topStack);
					Stack.pop();
				}
				Stack.pop();
			}
			else
				postFix.push(token);
		}
		tokens.pop();
	}
	while(!Stack.empty()){
		postFix.push(Stack.top());
		Stack.pop();
	}
}
//v2.0

void Parser::genCode(struct sock_filter *bpfCode, struct sock_fprog *bpfProg){
	string token;
	vector<BlockCode> codeStack;
	stack<string> expr;
	offOr = 0;
	offAnd = 2;
	int j = 0;
	while(!postFix.empty()){
		token = postFix.front();
		if(j == 0){
			if(isField(token) == 1){
				expr.push(token);
			}
			else{
				cout<<"Wrong syntax: "<<token<< " is not a \"field\" in IP, or TCP, or UDP header!"<<endl;
				exit(-1);
			}
		}
		else{
			if(isOperator(token) == 1){
				if(getPriority(token) == 1){		// logical operator
					if(codeStack.size() >= 2){
						if(token == "&&"){
							struct BlockCode b2 = codeStack.back();
							codeStack.pop_back();
							struct BlockCode b1 = codeStack.back();
							codeStack.pop_back();
							codeStack.push_back((struct BlockCode)genAnd(b1, b2));
						}
						else{
							struct BlockCode b2 = codeStack.back();
							codeStack.pop_back();
							struct BlockCode b1 = codeStack.back();
							codeStack.pop_back();
							codeStack.push_back((struct BlockCode)genOr(b1, b2));
						}
					}
				}
				else{		// comparison operator
					if(expr.size() >= 2){
						string value = expr.top();
						expr.pop();
						string field = expr.top();
						expr.pop();
						if(isField(field) == 1)
							codeStack.push_back((struct BlockCode)genCmp(field, value, token));
						else{
							cout<<"Wrong syntax!: \""<<field<<"\" is not a field"<<endl;
							exit(-1);
						}
						
					}
					else{
						cout<<"Wrong syntax!"<<endl;
						exit(-1);
					}
				}
			}
			else{// token is a value or field
				expr.push(token);
			}
		}
		postFix.pop();
		j++;
	}
	// gen return code
	struct BlockCode missRet = codeStack.back();
	codeStack.pop_back();
	codeStack.push_back(genRet(missRet));

	// gen filter IP packet
	struct BlockCode missIP = codeStack.back();
	codeStack.pop_back();
	codeStack.push_back(genFilterIP(missIP));


	// create bpf program
	struct BlockCode rs = codeStack.back();

	int codeLen = rs.codeSegment.size();
	if(codeLen <= 50){
		bpfProg->len = codeLen;
		for(int i = 0; i < codeLen; i++){
			bpfCode[i].code = rs.codeSegment.front().code;
			bpfCode[i].jt = rs.codeSegment.front().jt;
			bpfCode[i].jf = rs.codeSegment.front().jf;
			bpfCode[i].k = rs.codeSegment.front().k;
			rs.codeSegment.pop();
		}	
	}

	for(int j = 0; j < codeLen; j++){
			printf("Code: %.8X | Jump true: %u | Jump false: %u | K: %.8X\n", bpfCode[j].code, bpfCode[j].jt, bpfCode[j].jf, bpfCode[j].k);
	}
}

struct BlockCode Parser::genRet(struct BlockCode b1){
	struct BlockCode resultRet;
	int b1Size = b1.codeSegment.size();
	int i = 0;
	while(!b1.codeSegment.empty()){
		if(i == b1Size - 1){
			struct my_sock_filter stmt = b1.codeSegment.front();
			if(stmt.reverse != 1){
				stmt.jt = (uint8_t)0;
				stmt.jf = (uint8_t)1;
			}
			else{
				stmt.jt = (uint8_t)1;
				stmt.jf = (uint8_t)0;
			}
			resultRet.codeSegment.push(stmt);
			b1.codeSegment.pop();
			i++;
		}
		else{
			resultRet.codeSegment.push(b1.codeSegment.front());
			b1.codeSegment.pop();
			i++;
		}
	}
	resultRet.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_RET+BPF_K, 262144));
	resultRet.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_RET+BPF_K, 0));
	return resultRet;
}

struct BlockCode Parser::genFilterIP(struct BlockCode b1){
	struct BlockCode resultIP;
	uint8_t jumpFalse = (uint8_t)b1.codeSegment.size() - 1;
	resultIP.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12));
	resultIP.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x800, 0, jumpFalse, 0));

	while(!b1.codeSegment.empty()){
		resultIP.codeSegment.push(b1.codeSegment.front());
		b1.codeSegment.pop();
	}
	return resultIP;
}

struct BlockCode Parser::genCmp(string field, string value, string op){
	struct BlockCode resultCmp;
	uint32_t offset;
	uint8_t jumpCode = 0;
	uint8_t reverseBit = 0;
	if(op == "=="){
		jumpCode = BPF_JEQ;
		reverseBit = 0;
	}
	if(op == ">"){
		jumpCode = BPF_JGT;
		reverseBit = 0;
	}
	if(op == ">="){
		jumpCode = BPF_JGE;
		reverseBit = 0;
	}
	if(op == "!="){
		jumpCode = BPF_JEQ;
		reverseBit = 1;
	}
	if(op == "<"){
		jumpCode = BPF_JGE;
		reverseBit = 1;
	}
	if(op == "<="){
		jumpCode = BPF_JGT;
		reverseBit = 1;
	}

	if(field == "ipsrc" || field == "ipdst"){
		struct sockaddr_in sin;
		if(inet_aton(value.c_str(), &(sin.sin_addr)) != 1){
			cout<<"Wrong IP address syntax!: \""<<value<<"\""<<endl;
			exit(-1);
		} 
		uint32_t ip = ntohl((uint32_t)sin.sin_addr.s_addr);

		if(field == "ipsrc")
			offset = 26;
		else 
			offset = 30;
		resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset));
		resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, ip, 0, 0, reverseBit));
	}
	if(field == "ver"){
		uint8_t ver = (uint8_t)atoi(value.c_str());
		if(ver >= 64){		// version field's length = 4 bits -> max value = 63
			cout<<"Wrong \"version\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 14;
			resultCmp.codeSegment.push(((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset)));
			// version field's length = 4 bits  -> shifting right 4 bits
			resultCmp.codeSegment.push(((struct my_sock_filter)MY_BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 4)));
			resultCmp.codeSegment.push(((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, ver, 0, 0, reverseBit)));
		}
	}
	if(field == "iphdrlen"){
		uint8_t iphdrlen = (uint8_t)atoi(value.c_str());
		if(iphdrlen >= 64){	// header length field's length = 4 bits -> max value = 63
			cout<<"Wrong \"header length\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 14;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			// select the 4 bits last
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_ALU+BPF_AND+BPF_K, 0xF));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, iphdrlen, 0, 0, reverseBit));
		}
	}
	if(field == "tos"){
		uint8_t tos = (uint8_t)atoi(value.c_str());
		if(tos >= 256){ 	// type of service field length = 8 bits -> max value = 255
			cout<<"Wrong \"tos\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 15;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, tos, 0, 0, reverseBit));
		}
	}
	if(field == "ttlen"){
		uint16_t ttlen = (uint16_t)atoi(value.c_str());
		if(ttlen >= 65536){ // total length field's length = 16 bits -> max value = 65536
			cout<<"Wrong \"total length\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 16;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, ttlen, 0, 0, reverseBit));
		}
	}
	if(field == "ttl"){
		uint8_t ttl = (uint8_t)atoi(value.c_str());
		if(ttl >= 256){		// time-to-live field's length = 8 bits -> max value = 255
			cout<<"Wrong \"time-to-live\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 22;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, ttl, 0, 0, reverseBit));
		}
	}
	if(field == "proto"){
		uint8_t proto = (uint8_t)atoi(value.c_str());
		if(proto >= 256){	// protocol field's length = 8 bits -> max value = 255
			cout<<"Wrong \"protocol\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else{
			offset = 23;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, proto, 0, 0, reverseBit));
		}
	}

	if(field == "sport") {
		uint16_t sport = (uint16_t)atoi(value.c_str());
		if(sport >= 65566) { // source port field's length = 16bits -> max value = 65535
			cout<<"Wrong \"source port\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 34;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, sport, 0, 0, reverseBit));
		}
	}

	if(field == "dport") {
		uint16_t dport = (uint16_t)atoi(value.c_str());
		if(dport >= 65536) { // destination port field's length = 16bits -> max value = 65535
			cout<<"Wrong \"destination port\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 36;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, dport, 0, 0, reverseBit));
		}
	}

	if(field == "seqno") {
		uint32_t seqno = (uint32_t)atol(value.c_str());
		if(seqno > 0xffffffff) { // sequence number field's length = 32bits -> max value = 0xffffffff 
			cout<<"Wrong \"sequence number\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 38;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, seqno, 0, 0, reverseBit));
		}
	}

	if(field == "ackno") {
		uint32_t ackno = (uint32_t)atol(value.c_str());
		if(ackno > 0xffffffff) { //ack number field's length = 32bits -> max value = 0xffffffff
			cout<<"Wrong \"acknowledgment number\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 42;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, ackno, 0, 0, reverseBit));
		}
	}

	if(field == "tcphdrlen") {
		uint8_t tcphdrlen = (uint8_t)atoi(value.c_str());
		if(tcphdrlen >= 16 ) { // tcp header field's length = 4bits -> max value = 15
			cout<<"Wrong \"TCP header length value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 46;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			// tcp header length field's length = 4 bits  -> shifting right 4 bits
			resultCmp.codeSegment.push(((struct my_sock_filter)MY_BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, 4)));
			resultCmp.codeSegment.push(((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, tcphdrlen, 0, 0, reverseBit)));
		}
	}

	if(field == "urgflag" || field == "ackflag" || field == "pshflag" || field == "rstflag" || field == "synflag" || field == "finflag") {
		uint8_t flag = (uint8_t)atoi(value.c_str());
		if(flag > 1) {		// flag only store in 1 bit
			cout<<"Wrong \""<<field<<"\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			int mask = 0, bitShift = 0;
			if(field == "urgflag") {
				mask = 0x20;
				bitShift = 5;
			}
			if(field == "ackflag") {
				mask = 0x10;
				bitShift = 4;
			}
			if(field == "pshflag") {
				mask = 0x08;
				bitShift = 3;
			}
			if(field == "rstflag") {
				mask = 0x04;
				bitShift = 2;

			}
			if(field == "synflag") {
				mask = 0x02;
				bitShift = 1;
			}
			if(field == "finflag") {
				mask = 0x01;
				bitShift = 0;
			}
			offset = 47;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_B+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_ALU+BPF_AND+BPF_K, mask));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_ALU+BPF_RSH+BPF_K, bitShift));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, flag, 0, 0, reverseBit));
		}
	}

	if(field == "windowsiz") {
		uint16_t windowsiz = (uint16_t)atoi(value.c_str());
		if(windowsiz > 0xffff) { // window size field's length = 16bits -> max value = 0xffff
			cout<<"Wrong \"window size\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 48;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, windowsiz, 0, 0, reverseBit));
		}
	}

	if(field == "urgpnt") {
		uint16_t urgpnt = (uint16_t)atoi(value.c_str());
		if(urgpnt > 0xffff) { // urgent pointer field's length = 16bits -> max value = 0xffff
			cout<<"Wrong \"urgent pointer\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 52;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, urgpnt, 0, 0, reverseBit));
		}
	}

	if(field == "udplen") {
		uint16_t udplen = (uint16_t)atoi(value.c_str());
		if(udplen > 0xffff) { // urgent pointer field's length = 16bits -> max value = 0xffff
			cout<<"Wrong \"udp length\" value: \""<<value<<"\""<<endl;
			exit(-1);
		}
		else {
			offset = 38;
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_STMT(BPF_LD+BPF_H+BPF_ABS, offset));
			resultCmp.codeSegment.push((struct my_sock_filter)MY_BPF_JUMP(BPF_JMP+jumpCode+BPF_K, udplen, 0, 0, reverseBit));
		}
	}
	return resultCmp;
}


struct BlockCode Parser::genAnd(struct BlockCode b1, struct BlockCode b2){
	uint8_t b1Size = (uint8_t)b1.codeSegment.size();
	uint8_t b2Size = (uint8_t)b2.codeSegment.size();
	uint8_t jumpTrue;
	uint8_t jumpFalse;
	if(offOr != 0){
		offAnd =  b2Size + 2;
		jumpTrue = 0;
		jumpFalse = b2Size + 2 - offOr;
	}
	else{
		offAnd = b2Size + 2;
		jumpTrue = 0;
		jumpFalse = b2Size + 2 - 1;
	}
	struct BlockCode resultAnd;
	uint8_t i = 0;
	while(!b1.codeSegment.empty()){
		if(i == b1Size - 1){ // BPF_JUMP()
			struct my_sock_filter stmt = b1.codeSegment.front();
			if(stmt.reverse != 1){
				stmt.jt = jumpTrue;
				stmt.jf = jumpFalse;
			}
			else{
				stmt.jt = jumpFalse;
				stmt.jf = jumpTrue;
			}
			resultAnd.codeSegment.push(stmt);
			b1.codeSegment.pop();
			i++;
		}
		else{
			resultAnd.codeSegment.push(b1.codeSegment.front());
			b1.codeSegment.pop();
			i++;
		}
	}

	while(!b2.codeSegment.empty()){
		resultAnd.codeSegment.push(b2.codeSegment.front());
		b2.codeSegment.pop();
	}
	return resultAnd;
}

struct BlockCode Parser::genOr(struct BlockCode b1, struct BlockCode b2){
	uint8_t b1Size = (uint8_t)b1.codeSegment.size();
	uint8_t b2Size = (uint8_t)b2.codeSegment.size();
	uint8_t jumpTrue;
	uint8_t jumpFalse;
	if(offAnd != 0){
		offOr = b2Size + 2;
		jumpTrue = b2Size + 2 - offAnd;
		jumpFalse = 0;
	}
	else{
		offOr = b2Size + 2;
		jumpTrue = b2Size + 2 - 2;
		jumpFalse = 0;
	}
	struct BlockCode resultOr;
	uint8_t i = 0;
	while(!b1.codeSegment.empty()){
		if(i == b1Size - 1){
			struct my_sock_filter stmt = b1.codeSegment.front();
			if(stmt.reverse != 1){
				stmt.jt = jumpTrue;
				stmt.jf = jumpFalse;
			}
			else{
				stmt.jt = jumpFalse;
				stmt.jf = jumpTrue;
			}
			resultOr.codeSegment.push(stmt);
			b1.codeSegment.pop();
			i++;
		}
		else{
			resultOr.codeSegment.push(b1.codeSegment.front());
			b1.codeSegment.pop();
			i++;
		}
	}

	while(!b2.codeSegment.empty()){
		resultOr.codeSegment.push(b2.codeSegment.front());
		b2.codeSegment.pop();
	}
	return resultOr;
}