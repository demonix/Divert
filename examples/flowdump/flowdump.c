/*
 * socketdump.c
 * (C) 2019, all rights reserved,
 *
 * This file is part of WinDivert.
 *
 * WinDivert is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public
 * License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * WinDivert is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 * 
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/*
 * DESCRIPTION:
 *
 * usage: socketdump.exe [filter]
 *        socketdump.exe --block [filter]
 */

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "windivert.h"

// need link with Ws2_32.lib
#pragma comment(lib, "Ws2_32.lib")

 

BOOL is_private_ip(char *ip_address) {
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    BOOL result;

    // Parse the IP address
    if (inet_pton(AF_INET, ip_address, &(sa.sin_addr)) == 1) {
        // IPv4 address
        result = (ntohl(sa.sin_addr.s_addr) >> 24) == 10 ||
                 ((ntohl(sa.sin_addr.s_addr) >> 24) == 172 &&
                  (ntohl(sa.sin_addr.s_addr) >> 16 & 0xff) >= 16 &&
                  (ntohl(sa.sin_addr.s_addr) >> 16 & 0xff) <= 31) ||
                 ((ntohl(sa.sin_addr.s_addr) >> 24) == 192 &&
                  (ntohl(sa.sin_addr.s_addr) >> 16 & 0xff) == 168);
    } else if (inet_pton(AF_INET6, ip_address, &(sa6.sin6_addr)) == 1) {
        // IPv6 address
        result = (sa6.sin6_addr.s6_addr[0] == 0xfe &&
                  (sa6.sin6_addr.s6_addr[1] & 0xc0) == 0x80) ||
                 (sa6.sin6_addr.s6_addr[0] == 0xfd &&
                  (sa6.sin6_addr.s6_addr[1] & 0xc0) == 0x80) ||
                 memcmp(sa6.sin6_addr.s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 12) == 0 ||
                 memcmp(sa6.sin6_addr.s6_addr, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff", 14) == 0 ||
                 memcmp(sa6.sin6_addr.s6_addr, "\xfe\x80", 2) == 0 ||
                 memcmp(sa6.sin6_addr.s6_addr, "\xfc\x00", 2) == 0;
    } else {
        // Invalid IP address
        result = FALSE;
    }

    return result;
}


BOOL is_private_ip2(const char* ip_str) {
    struct in_addr addr;
    unsigned long ulAddr = INADDR_NONE;

    ulAddr = inet_addr(ip_str);

    u_long ip = ntohl(ulAddr);

    if ((ip >= 0x0A000000 && ip <= 0x0AFFFFFF) ||  // 10.0.0.0/8 range
        (ip >= 0xAC100000 && ip <= 0xAC1FFFFF) ||  // 172.16.0.0/12 range
        (ip >= 0xC0A80000 && ip <= 0xC0A8FFFF)) { // 192.168.0.0/16 range
        return TRUE; 
    }

    return FALSE;
}

/*
 * Entry.
 */
int __cdecl main(int argc, char **argv)
{
    HANDLE handle, process, console;
    INT16 priority = 1121;          // Arbitrary.
    const char *filter = "true", *err_str;
    char path[MAX_PATH+1];
    char local_str[INET6_ADDRSTRLEN+1], remote_str[INET6_ADDRSTRLEN+1];
    char *filename;
    DWORD path_len;
    WINDIVERT_ADDRESS addr;
  
    switch (argc)
    {
        case 1:
            break;
        case 2:
            filter = argv[1];
            break;
        default:
            fprintf(stderr, "usage: %s [filter]\n", argv[0]);
            exit(EXIT_FAILURE);
    }

    handle = WinDivertOpen(filter, WINDIVERT_LAYER_FLOW, priority, 
        WINDIVERT_FLAG_SNIFF | WINDIVERT_FLAG_RECV_ONLY);
    if (handle == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_INVALID_PARAMETER &&
            !WinDivertHelperCompileFilter(filter, WINDIVERT_LAYER_FLOW,
                NULL, 0, &err_str, NULL))
        {
            fprintf(stderr, "error: invalid filter \"%s\"\n", err_str);
            exit(EXIT_FAILURE);
        }
        fprintf(stderr, "error: failed to open the WinDivert device (%d)\n",
            GetLastError());
        return EXIT_FAILURE;
    }

    // Main loop:
    console = GetStdHandle(STD_OUTPUT_HANDLE);
    while (TRUE)
    {
        if (!WinDivertRecv(handle, NULL, 0, NULL, &addr))
        {
            fprintf(stderr, "failed to read packet (%d)\n", GetLastError());
            continue;
        }

        switch (addr.Event)
        {
            case WINDIVERT_EVENT_FLOW_ESTABLISHED:
                printf("ESTABLISHED");
                break;            
            case WINDIVERT_EVENT_FLOW_DELETED:
                printf("DELETED");
                break;            
            default:
                printf("???");
                break;
        }
      
        printf(" pid=");
        
        printf("%u", addr.Socket.ProcessId);
        

        printf(" program=");
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION , FALSE,
            addr.Socket.ProcessId);
        path_len = 0;
        DWORD path_len = 1024;
        if (process != NULL)
        {
            QueryFullProcessImageName(process,0, path, &path_len);
            if (path_len > 0) {
                //filename = PathFindFileName(path);
                filename = path;
                printf("%s", filename);
            } else if (addr.Socket.ProcessId == 4)
            {
                printf("Windows");
            }
            else
            {
                printf("???");
            }
            
            CloseHandle(process);
        }

        
        printf(" protocol=");
        switch (addr.Socket.Protocol)
        {
            case IPPROTO_TCP:
                printf("TCP");
                break;
            case IPPROTO_UDP:
                printf("UDP");
                break;
            case IPPROTO_ICMP:
                printf("ICMP");
                break;
            case IPPROTO_ICMPV6:
                printf("ICMPV6");
                break;
            default:
                printf("%u", addr.Socket.Protocol);
                break;
        }

        WinDivertHelperFormatIPv6Address(addr.Socket.LocalAddr, local_str,
            sizeof(local_str));
        if (addr.Socket.LocalPort != 0 || strcmp(local_str, "::") != 0)
        {
            printf(" local=");
            printf("[%s]:%u", local_str, addr.Socket.LocalPort);
        }

        WinDivertHelperFormatIPv6Address(addr.Socket.RemoteAddr, remote_str,
            sizeof(remote_str));
        if (addr.Socket.RemotePort != 0 || strcmp(remote_str, "::") != 0)
        {
            printf(" remote=");
            printf("[%s]:%u", remote_str, addr.Socket.RemotePort);

            printf(" remote_is_private=");
            if (is_private_ip(remote_str)){
                printf("TRUE");
            } else {
             printf("FALSE");   
            }
           
        }


        putchar('\n');
    }

    return 0;
}

