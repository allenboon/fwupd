/*
 * Copyright (C) 2018 Dell Inc.
 * All rights reserved.
 *
 * This software and associated documentation (if any) is furnished
 * under a license and may only be used or copied in accordance
 * with the terms of the license.
 *
 * This file is provided under a dual MIT/LGPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 * Dell Chooses the MIT license part of Dual MIT/LGPLv2 license agreement.
 *
 * SPDX-License-Identifier: LGPL-2.1+ OR MIT
 */

#pragma once

#include "config.h"

#include <fwupdplugin.h>

#include "fu-dell-dock-hid.h"
#include "fu-dell-dock-hub.h"
#include "fu-dell-dock-i2c-ec.h"
#include "fu-dell-dock-i2c-mst.h"
#include "fu-dell-dock-i2c-tbt.h"
#include "fu-dell-dock-status.h"
#include "fu-dell-dock-usb-usb4.h"

#define DELL_DOCK_DOCK1_INSTANCE_ID  "USB\\VID_413C&PID_B06E&hub&status"
#define DELL_DOCK_DOCK2_INSTANCE_ID  "USB\\VID_413C&PID_B06E&hub&salomon_mlk_status"
#define DELL_DOCK_EC_INSTANCE_ID     "USB\\VID_413C&PID_B06E&hub&embedded"
#define DELL_DOCK_TBT_INSTANCE_ID    "TBT-00d4b070"
#define DELL_DOCK_USB4_INSTANCE_ID   "TBT-00d4b071"
#define DELL_DOCK_VM5331_INSTANCE_ID "MST-panamera-vmm5331-259"
#define GR_USB_VID		   0x8087
#define GR_USB_PID		   0x0B40

gboolean
fu_dell_dock_set_power(FuDevice *device, guint8 target, gboolean enabled, GError **error);
void
fu_dell_dock_will_replug(FuDevice *device);

void
fu_dell_dock_clone_updatable(FuDevice *device);
