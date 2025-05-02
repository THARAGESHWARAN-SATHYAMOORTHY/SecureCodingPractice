Based on the sources provided, here is a summary of each topic covered in the chapter:

*Introduction and Memory Corruption Basics*

The chapter focuses on exploiting memory corruption issues in user-space software on the Android operating system, specifically targeting the ARM architecture. It covers well-known vulnerability classes like stack-based buffer overflows, discusses relevant implementation details for developing exploits, examines historical exploits, and includes a case study on advanced heap exploitation using a WebKit browser vulnerability.

Understanding exploits for memory corruption vulnerabilities requires abstraction; it's important to view the target machine's memory as a finite set of cells whose meaning is defined only by the target program's semantics, including implicit meanings from instruction types or functions treating regions as stack or heap. All exploitation methods for memory corruption involve *violating the implicit assumptions the target code makes about certain memory regions*. These violations are then used to manipulate the target program's state. Manipulation can be straightforward, like directing execution flow to attacker-controlled memory, or more complex, like leveraging existing program semantics based on violated assumptions ("weird machine programming"). The chapter focuses on common concepts affecting the Android platform on ARM devices, noting that many advanced techniques exist but depend on the specific vulnerability.

*Stack Buffer Overflows*

*   *ARM Architecture and the Stack:* The ARM Embedded ABI (EABI), like many ABIs, heavily utilizes the designated, thread-specific program stack. Key rules include:
    *   Passing parameters exceeding four on the stack using the push instruction.
    *   Allocating local variables that don't fit in registers on the current stack frame, especially those larger than 32-bit or referenced by pointers.
    *   Storing the return address for non-leaf functions on the stack.
*   *Stack Frames:* When a function using the stack is called, prologue code sets up a stack frame by saving registers and allocating space for local variables by adjusting the stack pointer. Epilogue code restores registers and tears down the frame. The stack grows from high virtual memory to low memory, meaning the stack pointer is decremented in the prologue and incremented in the epilogue. Nested calls create layered stack frames.
*   *Stack Pointer and Layout:* The stack pointer register (sp) is central to the stack concept, though it's primarily an ABI agreement and could be used for other purposes. A local variable on the stack can be treated by an attacker like any other memory location. Local stack variables are particularly interesting vulnerability targets because they reside close to inline control data, such as saved function return addresses. All local variables sit next to each other without interleaved control data; the stack frame layout is implicitly encoded in the compiled native code based on sp relative offsets.
*   *Vulnerability Mechanism:* Any bounds-checking bug affecting a local variable can be used to *overwrite the contents of other local variables or inline control data* with attacker-controlled values. This technique was first publicly documented by Aleph1 in "Smashing the Stack for Fun and Profit".
*   *Example:* Temporary character buffers or arrays allocated locally on the stack are a common vulnerability pattern. A trivial example is a getname function that uses the gets function, which is notoriously known for not performing bounds checking. If the input exceeds the buffer size (e.g., 32 characters for name), it will overwrite subsequent data on the stack.
*   *Exploitation in Example:* In the provided example's stack frame layout, providing more than 32 bytes of input first overwrites the local variable age (bytes 33-36) and then the saved return address (bytes 37-40). This allows an attacker to *redirect the execution flow* upon function return or simply control a local variable they couldn't otherwise change.
*   *Mitigation:* A generic mitigation (stack cookies) was implemented in GCC and enabled by default since the first Android release. Despite this, vulnerability-specific techniques can still attack applications protected by stack cookies, as seen in the zergRush exploit. Vanilla stack buffer overflows remain a useful introductory example.

*Heap Exploitation*

The heap is used for non-local objects that must exist longer than a single function's scope. Arrays and character buffers on the heap are also subject to bounds-checking issues, similar to the stack. Unlike local stack variables, the heap contains *in-bound allocation control metadata* for each object, and heap allocation lifetimes are not automatically managed by the compiler. These facts make heap-based vulnerabilities lend themselves to easier exploitation.

*Use-After-Free Issues*

*   *Definition:* A use-after-free (UAF) scenario occurs when application code accesses an object using a pointer after the object's memory has been marked as free by functions like free or the delete operator. It is a common and difficult-to-identify bug pattern. delete typically relies on free internally.
*   *Allocator Behavior:* Most heap allocators do not modify the contents of an allocation when freeing it, leaving the original data intact. Many store some control information about freed blocks at the beginning, but most of the original data remains.
*   *Scenarios when Freed Memory is Used:*
    *   *Memory not reused:* If the freed memory hasn't been used for a new allocation, accessing its contents yields the same data as when valid. This might not manifest as a visible bug, but a destructor might invalidate contents, causing a crash. It can also lead to *information leaks*.
    *   *Memory reused:* The freed allocation might be reused for a new allocation, causing two semantically different pointers to reference the same memory location. This often leads to a visible crash as the competing code interferes, e.g., one overwriting data that the other interprets as a memory address.
*   *Exploitation Requirement:* A freed block not reused is generally not useful (unless it can be freed again). Attackers often craft input to force the target application to allocate another object of similar size, reusing the just-freed spot. This methodology is heap allocator specific.

*Custom Allocators*

Heap allocators are typically part of the C runtime library (libc), not the operating system, though they are backed by OS-provided memory pages. Applications can use custom heap allocators optimized for performance. It is a misconception that WebKit-based browsers universally use TCmalloc; the Android browser uses *Bionic's embedded dlmalloc* for normal allocations.

*The Android dlmalloc Allocator*

*   *History and Versions:* Android's Bionic libc includes Doug Lea's dlmalloc allocator. Android used dlmalloc 2.8.3 until version 4.1.2 and has shipped with 2.8.6 since 4.2.
*   *Block Structure:* dlmalloc splits OS-allocated pages into blocks, each with an allocator-specific control header and the requested application memory. Memory requests are typically rounded up to multiples of eight bytes, allowing blocks of different original sizes rounded to the same value to be treated interchangeably.
*   *Control Data:* dlmalloc stores inline control data *two pointer sizes before the actual block*. These fields hold the sizes of the previous and current chunks, enabling navigation.
*   *Free Block Metadata:* Free blocks contain additional information at the beginning of the user data part. For blocks smaller than 256 bytes, this includes pointers to the next and previous free blocks of the same size, forming a doubly linked FIFO list. Larger blocks use a trie structure.
*   *Bins and Coalescing:* Small free blocks are categorized by size into bins, providing constant-time allocation lookups. When a block is freed, dlmalloc checks and *merges adjacent free blocks* into the current block (coalescing). Coalescing happens before binning.
*   *Implications for Exploitation:* Coalescing significantly impacts heap manipulation:
    *   *UAF:* Attackers must ensure adjacent blocks are in use to prevent coalescing and ensure a new allocation reuses the desired free spot. Coalescing can also shift the allocation if merged with a preceding block.
    *   *Buffer Overflows:* Coalescing with blocks at lower addresses can shift control structures out of control.
    *   Mitigation: Keeping small in-use allocations adjacent to exploited blocks can mitigate coalescing.
*   *Security Checks:* dlmalloc includes security checks, mainly affecting control data manipulation. Checks during free verify the next chunk's address is after the current, the previous chunk is on the heap, and a safe unlink check verifies forward and backward pointers when removing a chunk from free lists during coalescing or allocation. The safe unlink check mitigates overwriting arbitrary pointers but not locations already pointing to chunks, like bin list heads. Malloc checks are mostly limited to unlinking checks. Attacking application-specific pointers is often easier than exploiting scenarios not covered by checks.

*C++ Virtual Function Table Pointers*

*   *Polymorphism and Implementation:* C++ supports polymorphism via virtual functions, resolved at runtime. Compilers like GCC place a *virtual function table pointer (vftable)* at the beginning of an object in memory. This pointer points to a table containing function pointers. This is an optimization as instances have a fixed set of virtual functions. Vftables typically reside in the binary's text section. The vftable pointer is initialized by the object's constructor. Virtual function calls require memory indirection through the object instance, often allocated on the heap.
*   *Exploitation:* A memory corruption bug on the heap can allow an attacker to *manipulate the virtual function table pointer*. By making the vftable pointer point to a fake table on the heap, a subsequent virtual method call will use the fake table, diverting control flow to an attacker's chosen location.
*   *Weakness and Control:* This technique requires an indirection; the attacker cannot write the target function address directly into the object. The attacker needs to either:
    *   Leak a controllable heap address to use as the fake vftable pointer.
    *   Use application logic to overwrite the vftable pointer with a pointer to attacker-controlled data.

*WebKit Specific Allocator: The RenderArena*

*   *Purpose:* WebKit's rendering engine uses a custom allocator, the RenderArena, optimized for building the RenderTree (rendering information for a page). It needs to be fast because the RenderTree is rebuilt frequently. It allocates C++ objects representing RenderTree nodes.
*   *Structure:* The RenderArena is backed by large allocations from the main dlmalloc heap; it's a "heap on a heap". RenderArena allocations are typically fixed sizes, like 0x1018 bytes on ARM (0x1000 bytes plus header).
*   *Allocation Strategy:* The RenderArena strategy is simple: chunks are never coalesced. Free blocks of the same size are kept in a singly linked First-In-Last-Out (FILO) list for reuse. New blocks are created at the end of the current arena if no free spot exists. A new arena is allocated from dlmalloc if the current one is too small. This works well because only fixed-size C++ classes are allocated.
*   *Control Data:* No inline metadata is stored for allocated blocks. Free blocks have their first machine word replaced by a pointer to the next free block of the same size, forming the FILO list.
*   *Attack Opportunity:* The list pointer for the next free block is placed at the beginning of the free block. Since objects on the RenderArena are C++ classes derived from a base class with virtual functions, they have a virtual function table pointer at the beginning, which *overlaps with the linked list pointer*. The RenderArena allocator automatically points the virtual function table pointer to the previously freed block of the same size.
*   *Exploitation:* If an attacker can control the contents of an allocation of the same size and free it just before a use-after-free on a target object, the *native code flow can be redirected*. This can be exploited even if the full allocation contents cannot be controlled.
*   *Mitigation:* Google mitigated this technique by masking the linked list pointers with a runtime-generated magic value based on ASLR entropy. This value, with the most significant bit set, is unlikely to be a valid pointer.

*A History of Public Exploits*

The chapter details three historic exploits for user-space vulnerabilities on Android: two targeting vold (Android's mounting daemon) via different sockets, and one exploiting a Linux kernel vulnerability leveraged from user-space.

*GingerBreak*

*   *Target:* The vold daemon's handling of NETLINK messages. NETLINK sockets are local packet sockets for kernel/user-space communication and are not restricted by Android permissions, broadening the attack surface. Attackers can send fake messages expected from the kernel.
*   *Vulnerability:* A lack of proper bounds validation for the part_num variable in the handlePartitionAdded function within the DirectVolume class, used when processing NETLINK messages with DEVTYPE not set to 'disk'. The part_num value, supplied as the PARTN parameter in the NETLINK message, was interpreted as a signed integer and used as an index for the mPartMinors array, which is stored on the heap. The check if (part_num > mDiskNumParts) did not prevent negative indices.
*   *Primitive:* This allowed accessing elements before the mPartMinors array, enabling an attacker to *overwrite any 32-bit word* located in memory before the array with an attacker-controlled value. This is a classic *write-four primitive*.
*   *Fix:* The vulnerability was fixed in Android 2.3.4 by adding checks for negative indices (part_num < 1).
*   *Exploit (Sebastian Krahmer):* The public exploit did not require an information leak because it used Android's crash logging facility (assuming ADB shell access, which allows reading logs not accessible to normal apps). Affected Android versions lacked ASLR, making offsets stable.
    *   It determined the index offset from the mPartMinors array to the Global Offset Table (GOT).
    *   It crashed vold with invalid offsets and parsed the crash log's fault address to calculate the correct GOT index, knowing the GOT address from the vold binary's ELF headers.
    *   It then used the write-four primitive to **overwrite the GOT entry of the strcmp function with the address of the system function** from libc (address was stable due to no ASLR).
    *   The next time vold called strcmp, it executed system instead.
    *   The exploit sent a NETLINK request with a parameter string intended for comparison by strcmp; this string became the argument to the now-hooked system function, causing vold to *execute an attacker-provided binary*.
*   *Reliability:* This exploit is noted for its elegance and reliability due to simplicity (no native code payload or ROP) and target independence.

*zergRush*

*   *Target:* A stack buffer overflow vulnerability in the libsysutils library, specifically in the code parsing commands sent to Framework sockets (UNIX domain sockets), used by vold.
*   *Vulnerability:* The dispatchCommand function copied user input into a temporary local buffer (tmp) on the stack without bounds checks, and also added arguments to the argv array without bounds checks.
*   *Fix:* The vulnerability was fixed in Android 4.0 by adding a bounds check for the temporary buffer tmp.
*   *Attack Surface:* The relevant vold socket (/dev/socket/vold) was only accessible to the root user and the mount group. This limited the attack surface, allowing rooting via ADB shell (which runs as shell user, a member of mount) but not from processes like the browser. However, the same vulnerable code might be used by other processes with more accessible sockets.
*   *Exploit Strategy (with Stack Cookies):* Due to stack cookies protecting the return address, a simple buffer overflow was insufficient. The exploit used the array bounds checking failure on argv.
    *   It incremented the argc variable with 16 dummy elements.
    *   This caused the out-of-bounds entries of the argv array on the stack to **overlap with the temporary tmp buffer**.
    *   Writing to the tmp buffer then **overwrote the overlapping argv entries** with attacker-controlled pointers.
    *   When the function later called free on elements of argv, it used these controlled pointers, forcing a *use-after-free scenario for any heap object*.
    *   This UAF was then used to *hijack control flow using a virtual function table pointer*.
*   *Execution:* Android 2.3+ included the XN mitigation (no execution from data pages). To achieve code execution, the zergRush exploit utilized a simple *ROP chain* to set up arguments for a call to the system function, allowing it to invoke another binary as root, similar to GingerBreak.

*mempodroid*

*   *Target:* A vulnerability in the Linux kernel (versions 2.6.39 to 3.0, affecting Android 4.0) that allowed users with certain permissions to write to other process memory.
*   *Mechanism:* The Linux kernel exposes /proc/$pid/mem as a character device representing a process's virtual memory. While normally restricted to the process owner, the exploit bypassed restrictions by opening the target process's mem device and *cloning it to the target process's stdout and stderr*. By making the target program output attacker-controlled data (e.g., by printing an error message), this data was written to the target memory. Seeking in the mem device before program execution allowed controlling the specific memory write location.
*   *Target Binary:* The exploit targeted the set-uid run-as binary, which allows running commands as another user.
*   *Exploit Details:*
    *   The desired payload (code to execute) was provided as the username argument to run-as.
    *   run-as failed to look up the fake username and printed an error message to stderr (which was redirected to its own /proc/self/mem).
    *   The target write address was set by seeking in the mem device to the path of the error function that terminated the program via a call to exit.
    *   The attacker-controlled data from the error message *overwrote the native code* calling exit.
    *   To minimize attacker code, the hijacking targeted the call-site of the exit function.
    *   The injected code called setresuid(0) (setting the process's user IDs to root).
    *   The injected code then returned from the function as if no error occurred, causing run-as to continue its normal functionality and *spawn the attacker's provided command as root*.
*   *Reliability:* This exploit is highlighted for its elegance and simplicity in using existing program functionality.

*Exploiting the Android Browser (Case Study)*

*   *Target:* A specific use-after-free vulnerability (CVE-2011-3068) in WebKit's rendering code. It was fixed in WebKit upstream commit 100677 and merged into Android Browser 4.0.4+. The case study targets a vulnerable Android 4.0.1 device.
*   *Understanding the Bug:* The fix commit included a crash test case. Debugging revealed a SIGSEGV crash with the program counter (pc) at address 0. Analysis of the crash site assembly (WebCore::RenderObject::layoutIfNeededEv) showed the code loading a virtual function table pointer (ldr r0, [r4, #0]), then loading a function pointer from an offset within that table (ldr.w r3, [r0, #380]), and finally calling it (blx r3). Examination showed the loaded function pointer was 0x00000000, causing the crash. This confirmed a *RenderArena use-after-free scenario* where the virtual function table pointer was overwritten. The bug did not allow regaining JavaScript control after triggering the free. The goal is to control the contents of the fake virtual function pointer table.
*   *Control Challenge:* The virtual function call happens immediately after the object is freed, making it hard to allocate an arbitrary object of the same size (0x7c for RenderBlock) in its place. Redirecting the vftable pointer while the object is free is more promising. The key observation is that the function pointer offset (0x17c) is larger than the object size (0x7c), meaning the lookup goes past the object into subsequent memory.
*   *Controlling the Heap (Techniques):* Several methods are discussed to control the memory region immediately following the freed object:
    *   *Using CSS:* Allocate another RenderObject (like RenderListItem) in the space immediately following the UAF target object, ensuring it uses new, unallocated space by filling existing holes. While most RenderObject data is limited by CSS flags, RenderListItem's m_value/m_explicitValue members can hold a full 32-bit absolute position value. By padding with a dummy RenderBlock, the attacker can align a RenderListItem such that the function pointer offset (0x17c) lands precisely within these controllable fields. This allows controlling the full 32 bits of the program counter. However, this technique provides control only over the PC (r3) and not sufficient surrounding memory, making ROP/stack pivots difficult due to XN mitigation.
    *   *Using a Free Block:* Control the memory region after the UAF target by placing a controlled, freed block there. This involves allocating RenderArena-sized blocks on the main dlmalloc heap, setting their contents to desired values, adding small guard allocations, freeing the fake arena blocks (but not guards), and then forcing the allocation of a new RenderArena from one of these prepared blocks. Finally, allocate RenderObjects to fill existing arenas and ensure a RenderBlock (same type as UAF target) is the last allocation before the target is freed, ensuring the target's vftable points into the controlled free block. This method provides control over both the PC and sufficient surrounding memory for a stack pivot and ROP.
    *   *Using an Allocated Block:* Place a still allocated dlmalloc chunk containing controlled data immediately after the RenderArena chunk. The UAF object's vftable pointer points near the end of the arena, and the 0x17c offset lookup reads data from this adjacent, controlled allocated block, using it as the function pointer. This technique is useful because allocated blocks are less likely to be modified.

*Summary*

The chapter provided an overview of user-space memory corruption exploitation on ARM, focusing on stack and heap techniques relevant to Android. Heap attacks are often application and allocator specific but are common, with use-after-free scenarios allowing memory reuse and aliasing. Virtual function table pointers offer a direct method for hijacking execution from heap corruption. Historic exploits like GingerBreak (GOT modification via indexing), zergRush (stack/array overflow leading to UAF and ROP), and mempodroid (kernel vuln leveraged from user-space via /proc/mem) illustrated practical techniques. The WebKit browser UAF case study demonstrated advanced heap exploitation, detailing methods to control memory for diverting execution via a faked vftable, setting the stage for ROP in the next chapter.
