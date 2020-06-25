//#include "pch.h"
#include <stdio.h>

typedef unsigned int ipv4_t;    // u4
//typedef struct uint128 {
//    unsigned long long u1;
//    unsigned long long u2;
//    //constexpr uint128 operator+(uint128 x, uint128 y) noexcept
//    //{
//    //    const auto lo = x.lo + y.lo;
//    //    const auto carry = x.lo > lo;
//    //    const auto hi = x.hi + y.hi + carry;
//    //    return { hi, lo };
//    //}
//    constexpr uint128 operator+(uint128 x) noexcept
//    {
//        return x;
//    }
//} ipv6_t; // u128
typedef unsigned long long ipv6_t;
typedef unsigned long long ip6_t;
typedef struct tag_da_report {
    unsigned int last_time;
    unsigned int req_count;
    unsigned int rsp_count;
    unsigned int pass_count;
    unsigned int passrsp_count;
    unsigned int req_bytes;
    unsigned int rsp_bytes;
    unsigned int pass_bytes;
    unsigned int passrsp_bytes;
    unsigned int type;
    unsigned int len;
    char* data;
} phd_da_report_rec;
typedef struct tag_rw_lock { int _; } rwlock_t;
typedef struct tag_spin_lock { int _; } spinlock_t;
#define COMMON_MSG_SIZE 8192
typedef unsigned int u_int;
unsigned char phd_debug_print = 0;
#define printk printf
unsigned int phd_murmurhash32(const void*, size_t, int seed);
unsigned long ntohl(unsigned long);
unsigned long htonl(unsigned long);
unsigned short htons(unsigned short);
unsigned short ntohs(unsigned short);
typedef unsigned long long __uint128_t;
unsigned int phd_now = 0;
unsigned int phd_now_usec = 0;
void spin_lock_init(spinlock_t*);
void spin_lock(spinlock_t*);
void spin_unlock(spinlock_t*);
void rwlock_init(rwlock_t*);
void read_lock(rwlock_t*);
void read_unlock(rwlock_t*);
void write_lock(rwlock_t*);
void write_unlock(rwlock_t*);
#define PHD_PROCNAME "phd1"
int CHECK_IP_IN(unsigned int, unsigned int*);
#define SETARGDAT()
#define NET_PHD_PLUGIN_DNS 53
int phd_id = 1;
#define phd_send_msg()
int get_cycles();
unsigned int in_aton(const char*);
#define ERRORP printf
#define phd_vmemset()
#define IPPROTO_UDP 17
int PHD_RAND_UINT = 0;
int phd_get_current_time(int);

#pragma warning(disable:4616)

#define PHD_LOCK
#define PHD_UNLOCK

//#include "phd_core_dc.h"
#define PHD_DC_MAX_LABEL_LEN	63
#define PHD_DC_MAX_DC_LABEL_NUM 64
#define PHD_DC_MAX_NAME_LEN		256
#define PHD_DC_MAX_A_NUM        31

typedef struct {
    unsigned short area_id;
    unsigned char ips_class : 4,
        dummy_1 : 4;
    unsigned char flags;
}phd_dc_ipsection_info;

typedef struct {
    phd_dc_ipsection_info ipsection_info;
    ipv4_t ip;
}phd_dc_singleip_info;

phd_dc_ipsection_info* phd_dc_netc_area_map = 0;
phd_dc_singleip_info* phd_dc_singleip_area_map = 0;
unsigned int phd_dc_singleip_area_map_count = 0;
unsigned int phd_dc_no_answer_ttl = 600;

int phd_dc_parse_dnsname(char* dns_name, int len)
{
    int idx = 0;
    unsigned char label_len;
    while (1) {
        if (len < idx + 1)
            return 0;
        label_len = dns_name[idx++];
        if ((label_len & 0xc0) == 0xc0) {
            //compressed name
            if (len < idx + 1)
                return 0;
            idx++;
            break;
        }
        else if (label_len == 0)
            break;
        if (label_len > PHD_DC_MAX_LABEL_LEN)
            return 0;
        if (len < idx + label_len)
            return 0;
        if (idx + label_len > PHD_DC_MAX_NAME_LEN)
            return 0;
        idx += label_len;
    }
    return idx;
}

int phd_dc_parse_dnsname_label(char* dns_name, int name_len, unsigned short label_pos[], int label_pos_count)
{
    unsigned char label_len;
    int label_idx = 0;
    int idx = 0, check_name_idx = 0;
    while (1) {
        if (name_len < idx + 1 && label_idx < label_pos_count)
            return 0;
        label_len = dns_name[idx++];
        label_pos[label_idx++] = check_name_idx;
        check_name_idx++;
        if (label_len == 0)
            break;
        if (label_len > PHD_DC_MAX_LABEL_LEN)
            return 0;
        if (name_len < idx + label_len)
            return 0;
        check_name_idx += label_len;
        if (check_name_idx > PHD_DC_MAX_NAME_LEN)
            return 0;
        //check label
        idx += label_len;
    }
    return label_idx;
}

#define INLINE _inline
#define DNSCACHE_CACHE_IGNORE_MAX_IPS 32
unsigned int phd_dc_a_class_support = 0;

ipv4_t phd_dc_cache_ignore_ips[DNSCACHE_CACHE_IGNORE_MAX_IPS] = { 0 }; // 0 means match none, -1 means match all

INLINE int phd_dc_check_rrs(unsigned short req_type, unsigned short req_class, unsigned short answ_count, unsigned short auth_count, unsigned short add_count,
    unsigned int* least_ttl, unsigned short rrs_begin, unsigned short* answ_begin, unsigned short* auth_begin, unsigned short* addi_begin,
    unsigned short answ_a_begin[], unsigned short* answ_a_num, unsigned short ttl_pos[], unsigned short* ttl_num, unsigned short name_pos[], unsigned short* name_num,
    unsigned int check_ednso, unsigned int* p_ednso_len, unsigned int* p_ednso_data_len_idx, unsigned int* p_dnssec, unsigned char* gdns_data, unsigned char* p_gdns_data_len, ipv4_t* gdns_clientip, unsigned char* data, int data_len,
    int check_cache_ignore, int check_hijack, int check_a_zero, unsigned char* answ_ip_class, unsigned int* p_check_dnssec_rr, unsigned char* ip_name, int* p_ip_name_len, unsigned char* rr_weight, unsigned int* has_weight_data)
{
    int idx, rrs_num;
    unsigned int ttl;
    unsigned short c_len = 0, c_len_idx = 0;
    unsigned short rr_type, rr_class;
    unsigned char is_answ_a_begin;
    int hijack_rrs = 0, a_ip_zero = 0;
    int is_ednso;
    int r_begin;
    int ttl_count, name_count;
    phd_dc_ipsection_info ip_info;
    int ip_name_set = 0;

    idx = 0;
    rrs_num = 0;
    ttl_count = name_count = 0;
    if (least_ttl)
        *least_ttl = 0xffffffff;
    is_answ_a_begin = 0;
    if (answ_a_num)
        *answ_a_num = 0;
    if (answ_begin)
        *answ_begin = rrs_begin;
    if (auth_begin)
        *auth_begin = 0;
    if (addi_begin)
        *addi_begin = 0;
    is_ednso = r_begin = 0;

    while (idx < data_len) {
        //check rr
        //check name
        unsigned char label_len = 0;
        int name_len = 0;
        r_begin = idx;
        while (1) {
            if (data_len < idx + 1)
                return -1;
            label_len = data[idx++];
            name_len++;
            if ((label_len & 0xc0) == 0xc0) {
                //compressed name

                if (data_len < idx + 1)
                    return -1;
                if (data[idx] != 0x0c && name_pos && name_num && name_count < *name_num)
                    name_pos[name_count++] = idx - 1;
                idx++;
                name_len++;
                break;
            }
            else if (label_len == 0) {
                //root mark
                break;
            }

            if (label_len > PHD_DC_MAX_LABEL_LEN)
                return -1;
            if (data_len < idx + label_len)
                return -1;
            name_len += label_len;
            if (name_len > PHD_DC_MAX_NAME_LEN)
                return -1;
            idx += label_len;
        }

        //type
        if (idx + sizeof(unsigned short) > data_len)
            return -1;
        rr_type = ntohs(*(unsigned short*)(data + idx));
        idx += sizeof(unsigned short);
        if (rr_type == 41)
            is_ednso = 1;
        //class		
        if (idx + sizeof(unsigned short) > data_len)
            return -1;
        rr_class = ntohs(*(unsigned short*)(data + idx));
        idx += sizeof(unsigned short);
        //ttl
        if (idx + sizeof(unsigned int) > data_len)
            return -1;
        if (!check_ednso || !is_ednso) {
            ttl = ntohl(*(unsigned int*)(data + idx));
            if (least_ttl && ttl < *least_ttl)
                *least_ttl = ttl;
            if (ttl_pos && ttl_num && ttl_count < *ttl_num)
                ttl_pos[ttl_count++] = idx;
        }
        idx += sizeof(unsigned int);
        //len
        if (idx + sizeof(unsigned short) > data_len)
            return -1;
        c_len = ntohs(*(unsigned short*)(data + idx));
        c_len_idx = idx - r_begin;
        idx += sizeof(unsigned short);
        //data
        if (idx + c_len > data_len)
            return -1;
        if (req_type == 1 && req_class == 1 && rr_type == 1 && rr_class == 1 && rrs_num < answ_count && c_len == sizeof(ipv4_t)) {
            //req A In, answer rr A in, check ips
            ipv4_t a_ip = *(ipv4_t*)(data + idx);
            if (check_cache_ignore && CHECK_IP_IN(a_ip, phd_dc_cache_ignore_ips))
                return -2;
            if (check_hijack && phd_dc_check_hijack_resp(a_ip))
                hijack_rrs = 1;
            if (check_a_zero && !a_ip)
                a_ip_zero = 1;
            if (phd_dc_a_class_support && answ_ip_class && *answ_a_num < PHD_DC_MAX_A_NUM) {
                memset(&ip_info, 0, sizeof(phd_dc_ipsection_info));
                phd_dc_find_area_by_reqip(phd_dc_netc_area_map, phd_dc_singleip_area_map, a_ip, &ip_info);
                answ_ip_class[(*answ_a_num)] = ip_info.ips_class;
                RD_DEBUG("answ_ip_class[%d] = %d\n", *answ_a_num, answ_ip_class[(*answ_a_num)]);
                //first ip name
                if (!ip_name_set && p_ip_name_len && ip_name) {
                    unsigned short i = 0, j = r_begin + +rrs_begin, n_j = r_begin + +rrs_begin, compress_count = 0;
                    unsigned char* a_data = data - rrs_begin;
                    unsigned short a_data_len = data_len + rrs_begin;
                    while (i + 1 < *p_ip_name_len && j < a_data_len && compress_count < 16) {
                        if ((a_data[j] & 0xc0) == 0xc0) {
                            n_j = htons(*(unsigned short*)(a_data + j)) & 0x3fff;
                            RD_DEBUG("n_j %d j %d data_len %d\n", n_j, j, a_data_len);
                            if (j == n_j || n_j >= a_data_len)
                                break;
                            j = n_j;
                            compress_count++;
                            continue;
                        }
                        ip_name[i++] = a_data[j++];
                        if (a_data[j - 1] == 0) {
                            *p_ip_name_len = i;
                            ip_name_set = 1;
                            break;
                        }
                    }
                }
            }
        }
        if (name_pos && name_num && name_count < *name_num) {
            switch (rr_type) {
            case 5://cname : name
                RD_DEBUG("cname %d[%d] %d[%d]\n", idx + c_len - 2, data[idx + c_len - 2], idx + c_len - 1, data[idx + c_len - 1]);
                if (c_len >= 2 && (data[idx + c_len - 2] & 0xc0) == 0xc0 && data[idx + c_len - 1] != 0x0c) {
                    if (name_pos && name_num && name_count < *name_num)
                        name_pos[name_count++] = idx + c_len - 2;
                }
                break;
            case 15://mx : pri(2) name
                RD_DEBUG("mx %d[%d] %d[%d]\n", idx + c_len - 2, data[idx + c_len - 2], idx + c_len - 1, data[idx + c_len - 1]);
                if (c_len >= 4 && (data[idx + c_len - 2] & 0xc0) == 0xc0 && data[idx + c_len - 1] != 0x0c) {
                    if (name_pos && name_num && name_count < *name_num)
                        name_pos[name_count++] = idx + c_len - 2;
                }
                break;
            case 2://ns : name
                RD_DEBUG("NS %d[%d] %d[%d]\n", idx + c_len - 2, data[idx + c_len - 2], idx + c_len - 1, data[idx + c_len - 1]);
                if (c_len >= 2 && (data[idx + c_len - 2] & 0xc0) == 0xc0 && data[idx + c_len - 1] != 0x0c) {
                    if (name_pos && name_num && name_count < *name_num)
                        name_pos[name_count++] = idx + c_len - 2;
                }
                break;
            case 6://SOA : primaryns adminmail sn refresh retry expire ttl
            {
                int n_l = 0;
                //check primaryns
                n_l = phd_dc_parse_dnsname((char*)data + idx, c_len);
                if (n_l == 0)
                    return -1;
                RD_DEBUG("SOA n_l %d\n", n_l);
                RD_DEBUG("SOA1 %d[%d] %d[%d]\n", idx + n_l - 2, data[idx + n_l - 2], idx + c_len - 1, data[idx + n_l - 1]);
                if (n_l >= 2 && (data[idx + n_l - 2] & 0xc0) == 0xc0 && data[idx + n_l - 1] != 0x0c) {
                    name_pos[name_count++] = idx + n_l - 2;
                }
                //check adminmail
                RD_DEBUG("SOA2 %d[%d] %d[%d]\n", idx + c_len - 22, data[idx + c_len - 22], idx + c_len - 21, data[idx + c_len - 21]);
                if (c_len >= 22 && (data[idx + c_len - 22] & 0xc0) == 0xc0 && data[idx + c_len - 21] != 0x0c) {
                    if (name_pos && name_num && name_count < *name_num)
                        name_pos[name_count++] = idx + c_len - 22;
                }
            }
            break;
            case 12://ptr : name
                RD_DEBUG("ptr %d[%d] %d[%d]\n", idx + c_len - 2, data[idx + c_len - 2], idx + c_len - 1, data[idx + c_len - 1]);
                if (c_len >= 2 && (data[idx + c_len - 2] & 0xc0) == 0xc0 && data[idx + c_len - 1] != 0x0c) {
                    if (name_pos && name_num && name_count < *name_num)
                        name_pos[name_count++] = idx + c_len - 2;
                }
                break;
            }
        }
        idx += c_len;
        if (p_check_dnssec_rr && !(*p_check_dnssec_rr) && phd_dc_check_dnssec_rr(rr_type))
            *p_check_dnssec_rr = 1;

        rrs_num++;
        if (rrs_num <= answ_count) {
            if (rr_type == 1 && rr_class == 1) {
                if (!is_answ_a_begin && !*answ_a_num)
                    is_answ_a_begin = 1;
                if (is_answ_a_begin) {
                    if (*answ_a_num < PHD_DC_MAX_A_NUM)
                        answ_a_begin[(*answ_a_num)++] = rrs_begin + r_begin;
                    else
                        answ_a_begin[*answ_a_num] = idx;
                }
            }
            else if (is_answ_a_begin) {
                is_answ_a_begin = 0;
                if (*answ_a_num <= PHD_DC_MAX_A_NUM)
                    answ_a_begin[*answ_a_num] = rrs_begin + r_begin;
            }
        }
        else if (is_answ_a_begin) {
            is_answ_a_begin = 0;
            if (*answ_a_num <= PHD_DC_MAX_A_NUM)
                answ_a_begin[*answ_a_num] = rrs_begin + r_begin;
        }
        if (rrs_num == answ_count + 1)
            *auth_begin = rrs_begin + r_begin;
        if (rrs_num == answ_count + auth_count + 1)
            *addi_begin = rrs_begin + r_begin;
        if (check_ednso && is_ednso)
            break;
    }
    if (is_answ_a_begin) {
        is_answ_a_begin = 0;
        if (*answ_a_num <= PHD_DC_MAX_A_NUM)
            answ_a_begin[*answ_a_num] = rrs_begin + idx;
    }
    if (*auth_begin == 0)
        *auth_begin = rrs_begin + idx;
    if (*addi_begin == 0)
        *addi_begin = rrs_begin + idx;
    if (check_hijack && *answ_a_num > 0 && a_ip_zero)
        hijack_rrs = 1;
    if (rrs_num != answ_count + auth_count + add_count)
        return -1;
    if (idx != data_len)
        return -1;
    if (check_ednso && is_ednso) {
        //check the edns0 subnet
        if (p_ednso_data_len_idx)
            *p_ednso_data_len_idx = c_len_idx;
        if (p_ednso_len)
            *p_ednso_len = data_len - r_begin;
        phd_dc_check_edns0(data + r_begin, data_len - r_begin, p_dnssec, gdns_data, p_gdns_data_len, gdns_clientip, rr_weight, *answ_a_num, has_weight_data, 0);
    }
    if (answ_count == 0) {
        if (phd_dc_no_answer_ttl < *least_ttl)
            *least_ttl = phd_dc_no_answer_ttl;
    }
    if (ttl_num)
        *ttl_num = ttl_count;
    if (name_num)
        *name_num = name_count;
    if (hijack_rrs)
        return -3;
    return rrs_num;
}

