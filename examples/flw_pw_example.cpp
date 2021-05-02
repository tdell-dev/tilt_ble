#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <sys/types.h>
#include <sys/socket.h>

// $ gcc ble-scan.c -lbluetooth -o ble-scan

#define EIR_FLAGS                   0x01  /* flags */
#define EIR_UUID16_SOME             0x02  /* 16-bit UUID, more available */
#define EIR_UUID16_ALL              0x03  /* 16-bit UUID, all listed */
#define EIR_UUID32_SOME             0x04  /* 32-bit UUID, more available */
#define EIR_UUID32_ALL              0x05  /* 32-bit UUID, all listed */
#define EIR_UUID128_SOME            0x06  /* 128-bit UUID, more available */
#define EIR_UUID128_ALL             0x07  /* 128-bit UUID, all listed */
#define EIR_NAME_SHORT              0x08  /* shortened local name */
#define EIR_NAME_COMPLETE           0x09  /* complete local name */
#define EIR_TX_POWER                0x0A  /* transmit power level */
#define EIR_DEVICE_ID               0x10  /* device ID */
#define EIR_MANUFACTURE_SPECIFIC    0xFF

void process_data(uint8_t *data, size_t data_len, le_advertising_info *info);
int connecter(int sock, char dest[18]);
void deconnecter(int sock, uint16_t handle);

int main (int argc, char **argv)
{
    int sock, retval;
    int i, len;
    unsigned char buf[HCI_MAX_FRAME_SIZE];
    char btAddress[18];
    uint16_t handle;
    struct sockaddr_hci addr;
    struct hci_filter filter;
    int encore = 1;
    
    sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
    if (-1 == sock)
    {
        perror("socket"); return 1;
    }
    
    hci_filter_clear(&filter);
    hci_filter_all_ptypes(&filter);
    hci_filter_all_events(&filter);
    
    retval = setsockopt(sock, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)); 
    if (-1 == retval)
    {
        perror("setsockopt"); return 1;
    }
    
    memset(&addr, 0, sizeof(addr));
    addr.hci_family = AF_BLUETOOTH;
    addr.hci_dev = 0;
    retval = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (-1 == retval)
    {
        perror("bind"); return 1;
    }
    
	uint8_t scan_type = 0x00; /* Passive */
    uint16_t interval = htobs(0x0010);
	uint16_t window = htobs(0x0010);
    uint8_t own_type = 0x00;
	uint8_t filter_policy = 0x00; /* 1 -> Whitelist */	

    retval = hci_le_set_scan_parameters(sock, scan_type, interval, window, own_type, filter_policy, 1000);
    //retval = hci_le_set_scan_parameters(sock, 0, 0x10, 0x10, 0, 0, 1000);
    if (retval < 0)
    {
        perror("hci_le_set_scan_parameters"); //return 1;
    }
    
    retval = hci_le_set_scan_enable(sock, 1 /* 1 - turn on, 0 - turn off */, 0 /* 0-filtering disabled, 1-filter out duplicates */, 1000  /* timeout */);
    if (retval < 0)
    {
        perror("hci_le_set_scan_enable"); //return 1;
    }    
    
    do 
    {
        memset (buf, 0, sizeof(buf));
        retval = recv (sock, buf, sizeof(buf), 0);
        if (-1 == retval)
        {
            perror("recv"); return 1;
        }
        printf ("# ");
        for(i=0;i<retval;i++)
            printf ("0x%02X ", buf[i]);
            //printf ("%c ", buf[i]);
        printf ("(%d)\n\n", retval);
        /*printf ("# 0x%02X 0x%02X 0x%02X 0x%02X (%d)\n",
                    buf[0], buf[1],
                    buf[2], buf[3], retval);*/
        switch (buf[1]) 
        {
            case EVT_CMD_STATUS: // 0x0F
                if (buf[3]) 
                {
                    printf ("Erreur !\n");
                    encore = 0;
                } 
                else 
                {
                    printf ("Commande en cours\n");
                }
                break;
            case EVT_INQUIRY_RESULT: // 0x02
            printf ("Périphérique trouvé:\n");
                printf ("  * Adresse : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    buf[9], buf[8],
                    buf[7], buf[6],
                    buf[5], buf[4]);
                printf ("  * Classe  : 0x%02x%02x%02x\n\n",
                    buf[15], buf[14], buf[13]);
            break;
         case EVT_EXTENDED_INQUIRY_RESULT: // 0x2F
                printf ("Périphérique trouvé:\n");
                printf ("  * Adresse : %02x:%02x:%02x:%02x:%02x:%02x\n",
                    buf[9], buf[8],
                    buf[7], buf[6],
                    buf[5], buf[4]);
                printf ("  * Classe  : 0x%02x%02x%02x\n",
                    buf[14], buf[13], buf[12]);
                printf ("  * RSSI    : %d\n\n", // Received Signal Strength Indication
                    buf[17]);
                break;
            case EVT_INQUIRY_COMPLETE: // 0x01
                encore = 0;
                break;
            case EVT_LE_META_EVENT: // 0x3E
                len = retval;
                evt_le_meta_event *meta = (void *)(buf + (1 + HCI_EVENT_HDR_SIZE));

                len -= (1 + HCI_EVENT_HDR_SIZE);
                
                if (meta->subevent == EVT_LE_ADVERTISING_REPORT)
                {
                    printf("EVT_LE_ADVERTISING_REPORT (0x%02X)\n", meta->subevent);                    
                
                    le_advertising_info *info = (le_advertising_info *) (meta->data + 1);                    
                    int8_t rssi;
                
                    ba2str(&info->bdaddr, btAddress);
                    printf("* %s (%s) [ ", btAddress, (info->bdaddr_type == LE_PUBLIC_ADDRESS) ? "public" : "random");
                    for (i = 0; i < info->length; i++) 
                    {
                        printf("0x%02X ", info->data[i]);
                    }

                    rssi = *(info->data + info->length);
                    printf("] rssi = %d dBm\n", rssi);
               
                    if(info->length != 0)
                    {
                        int current_index = 0;
                        int data_error = 0;
                
                        while(!data_error && current_index < info->length)
                        {
                            size_t data_len = info->data[current_index];
                    
                            if(data_len + 1 > info->length)
                            {
                                printf("EIR data length is longer than EIR packet length. %d + 1 > %d", (int)data_len, info->length);
                                data_error = 1;
                            }
                            else
                            {
                                process_data(info->data + current_index + 1, data_len, info);
                                current_index += data_len + 1;
                            }
                        }
                    }
                    else
                        printf("info->length == 0 !\n");                        
                }
                else
                    printf("EVT_LE = 0x%02X\n", meta->subevent);
                
                //handle = connecter(sock, btAddress);
                
                //deconnecter(sock, handle);
                
                encore = 0;    
                break;
            default:
                break;
        }
    } 
    while (encore);

    retval = hci_le_set_scan_enable(sock, 0 /* 1 - turn on, 0 - turn off */, 0 /* 0-filtering disabled, 1-filter out duplicates */, 1000  /* timeout */);
    if (retval < 0)
    {
        perror("hci_le_set_scan_enable"); //return 1;
    }
    close (sock);
    
    return 0;
}

void process_data(uint8_t *data, size_t data_len, le_advertising_info *info)
{
    printf("process_data: %d octets\n", (int)data_len);
    if(data[0] == EIR_NAME_SHORT || data[0] == EIR_NAME_COMPLETE)
    {
        size_t name_len = data_len - 1;
        char *name = malloc(name_len + 1);
        memset(name, 0, name_len + 1);
        memcpy(name, &data[2], name_len);
        
        char addr[18];
        ba2str(&info->bdaddr, addr);
        
        printf("addr=%s name=%s\n", addr, name);
        
        free(name);
    }
    else if(data[0] == EIR_FLAGS)
    {
        printf("-> Flag type: len=%d\n", (int)data_len);
        int i;
        for(i=1; i<data_len; i++)
        {
          printf("\tFlag data: 0x%02X\n", data[i]); // 0x06 -> 0000 0110
        }
        /*
         bit 0 LE Limited Discoverable Mode
         bit 1 LE General Discoverable Mode
         bit 2 BR/EDR Supported
         bit 3 Simultaneous LE and BR/EDR to Same Device Capable (controller)
         bit 4 Simultaneous LE and BR/EDR to Same Device Capable (Host)
        */
    }
    else if(data[0] == EIR_MANUFACTURE_SPECIFIC)
    {
        printf("-> Manufacture specific type: len=%d\n", (int)data_len);
        
        // https://www.bluetooth.org/en-us/specification/assigned-numbers/company-identifiers
        // TODO int company_id = data[current_index + 2] 
        
        int i;
        for(i=1; i<data_len; i++)
        {
          printf("\tData: 0x%02X\n", data[i]);
        }
    }
    else if(data[0] == EIR_UUID128_SOME)
    {
        printf("-> UUID 128 type: len=%d\n", (int)data_len);
        printf("\t");
        int i;
        for(i=data_len-1; i>0; i--)
        {
          printf("%02x", data[i]);
        }
        printf("\n");
    }
    else
    {
        printf("-> Unknown type: type=0x%02X\n", data[0]);        
    }
}

int connecter(int sock, char dest[18])
{    
    struct hci_dev_info di;
    uint16_t handle;
    char addr[18];
    bdaddr_t bdaddr;    
    uint16_t interval, latency, max_ce_length, max_interval, min_ce_length;
	uint16_t min_interval, supervision_timeout, window;
	uint8_t initiator_filter, own_bdaddr_type, peer_bdaddr_type;
    int retval;
    char name[248];
    
    if (hci_devinfo(0, &di) < 0) 
    {
        perror("hci_devinfo");    
    }    
    ba2str(&di.bdaddr, addr);
    printf("Device  : %s [%s]\n", di.name, addr);        
    
    str2ba(dest, &bdaddr);
    
    interval = htobs(0x0004);
	window = htobs(0x0004);
    //initiator_filter = 0x01; /* Use white list */
    //peer_bdaddr_type = LE_RANDOM_ADDRESS;
	own_bdaddr_type = 0x00;
	min_interval = htobs(0x000F);
	max_interval = htobs(0x000F);
	latency = htobs(0x0000);
	supervision_timeout = htobs(0x0C80);
	min_ce_length = htobs(0x0001);
	max_ce_length = htobs(0x0001);
	retval = hci_le_create_conn(sock, interval, window, initiator_filter,
			peer_bdaddr_type, bdaddr, own_bdaddr_type, min_interval,
			max_interval, latency, supervision_timeout,
			min_ce_length, max_ce_length, &handle, 25000);
    if (retval < 0) 
    {
        perror("hci_le_create_conn");
        // TODO close(sock);
        return -1;
    }    
    printf("Handle : %d\n", handle);    
    
    /*if (hci_read_remote_name(sock, &bdaddr, sizeof(name), name, 25000) == 0)
		printf("Name : %s\n", name);*/
    
    //sleep(1);
    
    return handle;
}

void deconnecter(int sock, uint16_t handle)
{
    hci_disconnect(sock, handle, HCI_OE_USER_ENDED_CONNECTION, 10000);
}
