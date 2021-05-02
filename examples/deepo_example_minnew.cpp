// From https://stackoverflow.com/questions/38334255/basic-ble-client-with-d-bus-bluez

#include <iostream>
#include <chrono>
#include <thread>
#include <cstdint>

#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <glib.h>
#include <gio/gio.h>

#include <list>
#include <algorithm>

// sudo apt-get update
// sudo apt-get install bluez libbluetooth-dev libglib2.0-dev

// Compile with
// g++ -std=c++11 $(pkg-config --cflags glib-2.0 gobject-2.0 gio-2.0) ./bluez_dbus.cpp $(pkg-config --libs glib-2.0 gobject-2.0 gio-2.0 bluez) -o bluez_dbus

// Run with:
// sudo ./bluez_dbus

const u_char LE_ADV_REPORT = 0x02;

// https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/
const u_char EIR_FLAGS =                  0x01; /* flags */
const u_char EIR_UUID16_SOME =            0x02; /* 16-bit UUID, more available */
const u_char EIR_UUID16_ALL =             0x03; /* 16-bit UUID, all listed */
const u_char EIR_UUID32_SOME =            0x04; /* 32-bit UUID, more available */
const u_char EIR_UUID32_ALL =             0x05; /* 32-bit UUID, all listed */
const u_char EIR_UUID128_SOME =           0x06; /* 128-bit UUID, more available */
const u_char EIR_UUID128_ALL =            0x07; /* 128-bit UUID, all listed */
const u_char EIR_NAME_SHORT =             0x08; /* shortened local name */
const u_char EIR_NAME_COMPLETE =          0x09; /* complete local name */
const u_char EIR_TX_POWER =               0x0A; /* transmit power level */
const u_char EIR_DEVICE_ID =              0x10; /* device ID */
const u_char EIR_SERVICE_DATA =           0x16; /* service data */
const u_char EIR_MANUFACTURE_SPECIFIC =   0xFF;

void processData(uint8_t *data, size_t data_len, le_advertising_info *info)
{
    //printf("process_data: %d octets\n", (int)data_len);
    if (data[0] == EIR_NAME_SHORT || data[0] == EIR_NAME_COMPLETE)
    {
        size_t name_len = data_len - 1;
        char *name = (char *)malloc(name_len + 1);
        memset(name, 0, name_len + 1);
        memcpy(name, &data[1], name_len);

        char addr[18];
        ba2str(&info->bdaddr, addr);

        printf("addr=%s name=%s\n", addr, name);

        free(name);
    }
    else if (data[0] == EIR_FLAGS)
    {
        printf("-> Flag type: len=%d\n", (int)data_len);
        int i;
        for (i=1; i<data_len; i++)
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
    else if (data[0] == EIR_UUID16_ALL)
    {
        printf("-> UUID 16 All type: len=%d\n", (int)data_len);

        int i;
        printf("\tUUIDs: ");
        for (i=1; i<data_len; i += 2)
        {
            printf("0x%02X%02X ", data[i], data[i+1]);
        }
        printf("\n");
    }
    else if (data[0] == EIR_MANUFACTURE_SPECIFIC)
    {
        printf("-> Manufacture specific type: len=%d\n", (int)data_len);

        // https://www.bluetooth.com/specifications/assigned-numbers/company-identifiers/
        // TODO int company_id = data[current_index + 2] 

        // https://www.silabs.com/community/wireless/bluetooth/knowledge-base.entry.html/2017/11/14/bluetooth_advertisin-zCHh
        // int company_id = data[2] + 256 * data[1];
        // printf("Company ID: 0x%04X\n", company_id);

        int i;
        printf("\tData: ");
        for (i=1; i<data_len; i++)
        {
            printf("0x%02X ", data[i]);
        }
        printf("\n");
    }
    else if (data[0] == EIR_UUID128_SOME)
    {
        printf("-> UUID 128 type: len=%d\n", (int)data_len);
        printf("\t");
        int i;
        for (i=data_len-1; i>0; i--)
        {
            printf("%02x", data[i]);
        }
        printf("\n");
    }
    else if (data[0] == EIR_SERVICE_DATA)
    {
        printf("-> Service Data type: len=%d\n", (int)data_len);
        // Minew S1 data is 16 bytes
        if (data_len == 16)
        {
            // UUID = 0xFFE1 (little endian)
			// Not listed here: https://www.bluetooth.com/specifications/gatt/services/
            if (data[1] == 0xE1 && data[2] == 0xFF)
            {
                // Frame type 0xA1, Product Model 0x01
                if (data[3] == 0xA1 && data[4] == 0x01)
                {
                    uint8_t batteryPct = data[5];
                    printf("\tBattery percentage: %d\n", batteryPct);
                    float temperature = (float)data[6] + ((float)data[7] / 100.0);
                    printf("\tTemperature: %.2f C\n", temperature);
                    float humidity = (float)data[8] + ((float)data[9] / 100.0);
                    printf("\tHumidity: %.2f %%\n", humidity);
                }
            }
        }
    }
    else
    {
        printf("-> Unhandled AD type: 0x%02X\n", data[0]);
    }
}

// based on hcitool lescan
bool receiveAdv(int dd, std::chrono::seconds timeout, std::list<std::string> &devices)
{
    u_char buff[HCI_MAX_EVENT_SIZE];
    u_char *ptr;
    hci_filter filter;

    hci_filter_clear(&filter);
    hci_filter_set_ptype(HCI_EVENT_PKT, &filter);
    hci_filter_set_event(EVT_LE_META_EVENT, &filter);

    if (setsockopt(dd, SOL_HCI, HCI_FILTER, &filter, sizeof(filter)) < 0)
    {
        std::cerr << "Could not set socket options" << std::endl;
        return false;
    }

    using namespace std::chrono;
    time_point<steady_clock> start = steady_clock::now();
    while (steady_clock::now() - start < timeout)
    {
        if (read(dd, buff, sizeof(buff)) < 0)
        {
            std::this_thread::sleep_for(milliseconds(20));
            continue;
        }

        ptr = buff + (1 + HCI_EVENT_HDR_SIZE);
        evt_le_meta_event *meta = reinterpret_cast<evt_le_meta_event *>(ptr);

        if (meta->subevent != LE_ADV_REPORT)
            continue;

        le_advertising_info *info = reinterpret_cast<le_advertising_info *>(meta->data + 1);
        char addr[18];
        ba2str(&info->bdaddr, addr);
        int rssi = info->data[info->length]; //intentional, isn't out of bounds

        // Add new devices to list
        std::list<std::string>::iterator it = devices.begin();
        bool found = false;
        while (it != devices.end())
        {
            if (*it == std::string(addr))
                found = true;
            it++;
        }
        if (!found)
        {
            std::cout << "Detected device: " << addr << " " << rssi << std::endl;
            devices.push_back(std::string(addr));
        }

        if (info->length != 0)
        {
            int current_index = 0;
            int data_error = 0;
            while (!data_error && current_index < info->length)
            {
                size_t data_len = info->data[current_index];
                if (data_len + 1 > info->length)
                {
                    printf("EIR data length is longer than EIR packet length. %d + 1 > %d", (int)data_len, info->length);
                    data_error = 1;
                }
                else
                {
                    std::string btaddr(addr);
                    if (btaddr == "E2:7C:3E:DF:72:61")//"AC:23:3F:A0:02:B6" || btaddr == "AC:23:3F:A0:01:C4" || btaddr == "AC:23:3F:A0:3B:73" || btaddr == "AC:23:3F:A0:01:F8")
                    {
                        processData(info->data + current_index + 1, data_len, info);
                    }
                    current_index += data_len + 1;
                }
            }
        }
    }

    return true;
}

bool scan(unsigned timeout, std::list<std::string> &devices)
{
    int devId = hci_get_route(nullptr);
    int dd = hci_open_dev(devId);
    if (devId < 0 || dd < 0) {
        std::cerr << "Could not open device" << std::endl;
        return false;
    }

    uint8_t localAddr = LE_PUBLIC_ADDRESS; //LE_PUBLIC_ADDRESS to use public on local device, LE_RANDOM_ADDRESS to use random
    uint8_t scanType = 0x01; //0x01 = active, 0x00 = passive
    uint8_t filterPolicy = 0x00; //0x00 = don't use whitelist, 0x01 = use whitelist
    uint16_t interval = htobs(0x0010); //no idea, default for all except 'g' or 'l' filters that use htobs(0x0012)
    uint16_t window = htobs(0x0010); //no idea, default for all except 'g' or 'l' filters that use htobs(0x0012)
    uint8_t filterDup = 0x00; // 0x01 = filter duplicates, 0x00 = receive duplicates
    int hciTimeout = 10000; // this is timeout for communication with the local adapter, not scanning

    if (hci_le_set_scan_parameters(dd, scanType, interval, window, localAddr, filterPolicy, hciTimeout) < 0) {
        std::cerr << "Set scan parameters failed" << std::endl;
        hci_close_dev(dd);
        return false;
    }

    uint8_t scanEnable = 0x01;
    if (hci_le_set_scan_enable(dd, scanEnable, filterDup, hciTimeout) < 0) {
        std::cerr << "Enable scan failed" << std::endl;
        hci_close_dev(dd);
        return false;
    }

    if (receiveAdv(dd, std::chrono::seconds(timeout), devices) < 0) {
        std::cerr << "Could not receive advertising events" << std::endl;
        hci_close_dev(dd);
        return false;
    }

    uint8_t scanDisable = 0x00;
    if (hci_le_set_scan_enable(dd, scanDisable, filterDup, hciTimeout) < 0) {
        std::cerr << "Disable scan failed" << std::endl;
        hci_close_dev(dd);
        return false;
    }

    hci_close_dev(dd);
    return true;
}

// https://stackoverflow.com/questions/2896600/how-to-replace-all-occurrences-of-a-character-in-string
std::string ReplaceAll(std::string str, const std::string& from, const std::string& to)
{
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

GDBusProxy *connect(const char *addr)
{
    GError *err = nullptr;

    std::string ble_addr(addr);
    ble_addr = ReplaceAll(ble_addr, ":", "_");

    std::string objPath = ReplaceAll(std::string("/org/bluez/hci0/dev_[DEV_ADDR]"), std::string("[DEV_ADDR]"), ble_addr);
    std::cout << "Connect path: " << objPath << std::endl;

//    char objPath[sizeof("/org/bluez/hci0/dev_AC_23_3F_A0_02_B6")] = "/org/bluez/hci0/dev_AC_23_3F_A0_02_B6";
    GDBusProxy *devProxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE, nullptr, "org.bluez", objPath.c_str(), "org.bluez.Device1", nullptr, &err);
    if (!devProxy) {
        std::cerr << "Device " << addr << " not available: " << err->message << " (" << err->code << ")" << std::endl;
        g_clear_error(&err);
        return nullptr;
    }
    if (g_dbus_proxy_call_sync(devProxy, "Connect", nullptr, G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &err)) {
        if (!g_dbus_proxy_call_sync(devProxy, "Pair", nullptr, G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &err)) {
            std::cerr << "Failed to pair: " << err->message << " (" << err->code << ")" << std::endl;
            g_clear_error(&err);
            return nullptr;
        }
    }
    else {
        std::cerr << "Failed to connect: " << err->message << " (" << err->code << ")" << std::endl;
        g_clear_error(&err);
        devProxy = nullptr;
    }
    return devProxy;
}

bool disconnect(GDBusProxy *devProxy)
{
    if (devProxy != nullptr)
    {
        GError *err = nullptr;
        if (!g_dbus_proxy_call_sync(devProxy, "Disconnect", nullptr, G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &err)) {
            std::cerr << "Failed to disconnect - " << err->message << "(" << err->code << ")" << std::endl;
            g_clear_error(&err);
            return false;
        }
    }
    return true;
}

GVariant *read(const char *addr)
{
//    const char *objPath("/org/bluez/hci0/dev_AC_23_3F_A0_02_B6/service0013/char0014");
	std::string ble_addr(addr);
	ble_addr = ReplaceAll(ble_addr, ":", "_");

	std::string objPath = ReplaceAll(std::string("/org/bluez/hci0/dev_[DEV_ADDR]/service0013/char0014"), std::string("[DEV_ADDR]"), ble_addr);
	std::cout << "Read path: " << objPath << std::endl;

    GVariantBuilder *b = g_variant_builder_new(G_VARIANT_TYPE("({sv})"));
    g_variant_builder_add(b, "{sv}", "offset", g_variant_new_uint16(0));
    GVariant *args = g_variant_builder_end(b);

    GError *err = nullptr;
    GDBusProxy *charProxy = g_dbus_proxy_new_for_bus_sync(G_BUS_TYPE_SYSTEM, G_DBUS_PROXY_FLAGS_NONE, nullptr, "org.bluez", objPath.c_str(), "org.bluez.GattCharacteristic1", nullptr, &err);
    GVariant *ret = g_dbus_proxy_call_sync(charProxy, "ReadValue", args, G_DBUS_CALL_FLAGS_NONE, -1, nullptr, &err);
    if (ret == FALSE) {
        std::cerr << "Failed to read - " << err->message << "(" << err->code << ")" << std::endl;
        g_clear_error(&err);
        return nullptr;
    }

    return ret;
}

int main()
{
    std::list<std::string> devices;
    scan(10, devices);

    std::list<std::string>::iterator it = devices.begin();
    while (it != devices.end())
    {
        std::cout << "--------------- " << *it << " ---------------" << std::endl;

        GDBusProxy *proxy = connect((*it).c_str());
        if (proxy) {
            GVariant *ret = read((*it).c_str());
        }
        disconnect(proxy);

        it++;
    }

//    GDBusProxy *proxy = connect("AC:23:3F:A0:3B:73");
//    if (proxy) {
//        GVariant *ret = read("AC:23:3F:A0:3B:73");
//    }
//    disconnect(proxy);

    return 0;
}

