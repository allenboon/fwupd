/*
 * Copyright (C) 2017 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <gio/gio.h>

/* SMBIOS */
#define REDFISH_SMBIOS_TABLE_TYPE 0x2a /* 42 */

#define REDFISH_PROTOCOL_REDFISH_OVER_IP 0x04

#define REDFISH_CONTROLLER_INTERFACE_TYPE_NETWORK_HOST 0x40

#define REDFISH_INTERFACE_TYPE_USB_NETWORK    0x02
#define REDFISH_INTERFACE_TYPE_PCI_NETWORK    0x03
#define REDFISH_INTERFACE_TYPE_USB_NETWORK_V2 0x04
#define REDFISH_INTERFACE_TYPE_PCI_NETWORK_V2 0x05

#define REDFISH_IP_ASSIGNMENT_TYPE_STATIC      0x00
#define REDFISH_IP_ASSIGNMENT_TYPE_DHCP	       0x02
#define REDFISH_IP_ASSIGNMENT_TYPE_AUTO_CONFIG 0x03
#define REDFISH_IP_ASSIGNMENT_TYPE_HOST_SELECT 0x04

#define REDFISH_IP_ADDRESS_FORMAT_UNKNOWN 0x00
#define REDFISH_IP_ADDRESS_FORMAT_V4	  0x01
#define REDFISH_IP_ADDRESS_FORMAT_V6	  0x02

/* EFI */
#define REDFISH_EFI_INFORMATION_GUID "16faa37e-4b6a-4891-9028-242de65a3b70"

#define REDFISH_EFI_INFORMATION_INDICATIONS    "RedfishIndications"
#define REDFISH_EFI_INFORMATION_FW_CREDENTIALS "RedfishFWCredentials"
#define REDFISH_EFI_INFORMATION_OS_CREDENTIALS "RedfishOSCredentials"

#define REDFISH_EFI_INDICATIONS_FW_CREDENTIALS 0x00000001
#define REDFISH_EFI_INDICATIONS_OS_CREDENTIALS 0x00000002

/* shared */
gchar *
fu_redfish_common_buffer_to_ipv4(const guint8 *buffer);
gchar *
fu_redfish_common_buffer_to_ipv6(const guint8 *buffer);
gchar *
fu_redfish_common_buffer_to_mac(const guint8 *buffer);

gchar *
fu_redfish_common_fix_version(const gchar *version);
gboolean
fu_redfish_common_parse_version_lenovo(const gchar *version,
				       gchar **out_build,
				       gchar **out_version,
				       GError **error);
