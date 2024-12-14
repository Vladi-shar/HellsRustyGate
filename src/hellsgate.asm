; Hell's Gate
; Dynamic system call invocation
;
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	w_system_call DWORD 000h

.code
	hells_gate PROC
		mov w_system_call, 000h
		mov w_system_call, ecx
		ret
	hells_gate ENDP

	hell_descent PROC
		mov r10, rcx
		mov eax, w_system_call

		syscall
		ret
	hell_descent ENDP
end
