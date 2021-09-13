/*
 * Copyright (C) 2020 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "fu-security-attr.h"

#include <config.h>
#include <glib/gi18n.h>
#include <json-glib/json-glib.h>

#include "fwupd-security-attr-private.h"
#include "fwupd-enums-private.h"
#include "fu-security-attrs-private.h"

gchar *
fu_security_attr_get_name(FwupdSecurityAttr *attr)
{
	const gchar *appstream_id = fwupd_security_attr_get_appstream_id(attr);
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BIOSWE) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI write"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_BLE) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI lock"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_SMM_BWP) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI BIOS region"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SPI_DESCRIPTOR) == 0) {
		/* TRANSLATORS: Title: SPI refers to the flash chip in the computer */
		return g_strdup(_("SPI BIOS Descriptor"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_ACPI_DMAR) == 0) {
		/* TRANSLATORS: Title: DMA as in https://en.wikipedia.org/wiki/DMA_attack  */
		return g_strdup(_("Pre-boot DMA protection"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ENABLED) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel */
		return g_strdup(_("Intel BootGuard"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_VERIFIED) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * verified boot refers to the way the boot process is verified */
		return g_strdup(_("Intel BootGuard verified boot"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_ACM) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * ACM means to verify the integrity of Initial Boot Block */
		return g_strdup(_("Intel BootGuard ACM protected"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_POLICY) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * error policy is what to do on failure */
		return g_strdup(_("Intel BootGuard error policy"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_BOOTGUARD_OTP) == 0) {
		/* TRANSLATORS: Title: BootGuard is a trademark from Intel,
		 * OTP = one time programmable */
		return g_strdup(_("Intel BootGuard OTP fuse"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ENABLED) == 0) {
		/* TRANSLATORS: Title: CET = Control-flow Enforcement Technology,
		 * enabled means supported by the processor */
		return g_strdup(_("Intel CET Enabled"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_CET_ACTIVE) == 0) {
		/* TRANSLATORS: Title: CET = Control-flow Enforcement Technology,
		 * active means being used by the OS */
		return g_strdup(_("Intel CET Active"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_SMAP) == 0) {
		/* TRANSLATORS: Title: SMAP = Supervisor Mode Access Prevention */
		return g_strdup(_("Intel SMAP"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_ENCRYPTED_RAM) == 0) {
		/* TRANSLATORS: Title: Memory contents are encrypted, e.g. Intel TME */
		return g_strdup(_("Encrypted RAM"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_IOMMU) == 0) {
		/* TRANSLATORS: Title:
		 * https://en.wikipedia.org/wiki/Input%E2%80%93output_memory_management_unit */
		return g_strdup(_("IOMMU"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_LOCKDOWN) == 0) {
		/* TRANSLATORS: Title: lockdown is a security mode of the kernel */
		return g_strdup(_("Linux kernel lockdown"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_TAINTED) == 0) {
		/* TRANSLATORS: Title: if it's tainted or not */
		return g_strdup(_("Linux kernel"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_KERNEL_SWAP) == 0) {
		/* TRANSLATORS: Title: swap space or swap partition */
		return g_strdup(_("Linux swap"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_RAM) == 0) {
		/* TRANSLATORS: Title: sleep state */
		return g_strdup(_("Suspend-to-ram"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_SUSPEND_TO_IDLE) == 0) {
		/* TRANSLATORS: Title: a better sleep state */
		return g_strdup(_("Suspend-to-idle"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_PK) == 0) {
		/* TRANSLATORS: Title: PK is the 'platform key' for the machine */
		return g_strdup(_("UEFI platform key"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_UEFI_SECUREBOOT) == 0) {
		/* TRANSLATORS: Title: SB is a way of locking down UEFI */
		return g_strdup(_("UEFI secure boot"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_RECONSTRUCTION_PCR0) == 0) {
		/* TRANSLATORS: Title: the PCR is rebuilt from the TPM event log */
		return g_strdup(_("TPM PCR0 reconstruction"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_TPM_VERSION_20) == 0) {
		/* TRANSLATORS: Title: TPM = Trusted Platform Module */
		return g_strdup(_("TPM v2.0"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_MANUFACTURING_MODE) == 0) {
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s manufacturing mode"), kind);
		}
		/* TRANSLATORS: Title: MEI = Intel Management Engine */
		return g_strdup(_("MEI manufacturing mode"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_OVERRIDE_STRAP) == 0) {
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s override"), kind);
		}
		/* TRANSLATORS: Title: MEI = Intel Management Engine, and the
		 * "override" is the physical PIN that can be driven to
		 * logic high -- luckily it is probably not accessible to
		 * end users on consumer boards */
		return g_strdup(_("MEI override"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_MEI_VERSION) == 0) {
		/* TRANSLATORS: Title: MEI = Intel Management Engine */
		const gchar *kind = fwupd_security_attr_get_metadata(attr, "kind");
		const gchar *version = fwupd_security_attr_get_metadata(attr, "version");
		if (kind != NULL && version != NULL) {
			/* TRANSLATORS: Title: %1 is ME kind, e.g. CSME/TXT, %2 is a version number
			 */
			return g_strdup_printf(_("%s v%s"), kind, version);
		}
		if (kind != NULL) {
			/* TRANSLATORS: Title: %s is ME kind, e.g. CSME/TXT */
			return g_strdup_printf(_("%s version"), kind);
		}
		return g_strdup(_("MEI version"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_UPDATES) == 0) {
		/* TRANSLATORS: Title: if firmware updates are available */
		return g_strdup(_("Firmware updates"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_ATTESTATION) == 0) {
		/* TRANSLATORS: Title: if we can verify the firmware checksums */
		return g_strdup(_("Firmware attestation"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_FWUPD_PLUGINS) == 0) {
		/* TRANSLATORS: Title: if the fwupd plugins are all present and correct */
		return g_strdup(_("fwupd plugins"));
	}
	if (g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_DCI_ENABLED) == 0 ||
	    g_strcmp0(appstream_id, FWUPD_SECURITY_ATTR_ID_INTEL_DCI_LOCKED) == 0) {
		/* TRANSLATORS: Title: Direct Connect Interface (DCI) allows
		 * debugging of Intel processors using the USB3 port */
		return g_strdup(_("Intel DCI debugger"));
	}

	/* we should not get here */
	return g_strdup(fwupd_security_attr_get_name(attr));
}

const gchar *
fu_security_attr_get_result(FwupdSecurityAttr *attr)
{
	FwupdSecurityAttrResult result = fwupd_security_attr_get_result(attr);
	if (result == FWUPD_SECURITY_ATTR_RESULT_VALID) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Valid");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_VALID) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Invalid");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_ENABLED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Enabled");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_ENABLED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Disabled");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_LOCKED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Locked");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_LOCKED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Unlocked");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_ENCRYPTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Encrypted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_ENCRYPTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Unencrypted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_TAINTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Tainted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_TAINTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Untainted");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_FOUND) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Found");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_FOUND) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Not found");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_SUPPORTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Supported");
	}
	if (result == FWUPD_SECURITY_ATTR_RESULT_NOT_SUPPORTED) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("Not supported");
	}

	/* fallback */
	if (fwupd_security_attr_has_flag(attr, FWUPD_SECURITY_ATTR_FLAG_SUCCESS)) {
		/* TRANSLATORS: Suffix: the HSI result */
		return _("OK");
	}

	/* TRANSLATORS: Suffix: the fallback HSI result */
	return _("Failed");
}

/**
 * fu_security_attrs_to_json_string：
 * Convert security attribute to JSON string.
 * @attrs: a pointer for a FuSecurityAttrs data structure.
 * @error: return location for an error
 *
 * fu_security_attrs_to_json_string() converts FuSecurityAttrs and return the
 * string pointer. The converted JSON format is shown as follows:
 * {
 *     "SecurityAttributes": [
 *         {
 *              "name": "aaa",
 *              "value": "bbb"
 *         }
 *     ]
 *  }
 *
 * Returns: A string and NULL on fail.
 *
 * Since: 1.7.0
 *
 */
gchar *
fu_security_attrs_to_json_string(FuSecurityAttrs *attrs, GError **error)
{
	g_autofree gchar *data = NULL;
	g_autoptr(JsonGenerator) json_generator = NULL;
	g_autoptr(JsonBuilder) builder = json_builder_new();
	g_autoptr(JsonNode) json_root = NULL;
	fu_security_attrs_to_json(attrs, builder);
	json_root = json_builder_get_root(builder);
	json_generator = json_generator_new();
	json_generator_set_pretty(json_generator, TRUE);
	json_generator_set_root(json_generator, json_root);
	data = json_generator_to_data(json_generator, NULL);
	if (data == NULL) {
		g_set_error(error,
			    FWUPD_ERROR,
			    FWUPD_ERROR_INTERNAL,
			    "Failed to convert security attribute to json.");
		return NULL;
	}
	return g_steal_pointer(&data);
}

void
fu_security_attrs_to_json(FuSecurityAttrs *attrs, JsonBuilder *builder)
{
	g_autoptr(GPtrArray) items = NULL;
	g_autoptr(GError) error = NULL;
	json_builder_begin_object(builder);
	json_builder_set_member_name(builder, "SecurityAttributes");
	json_builder_begin_object(builder);
	items = fu_security_attrs_get_all(attrs);
	for (guint i = 0; i < items->len; i++) {
		FwupdSecurityAttr *attr = g_ptr_array_index(items, i);
		json_builder_set_member_name(builder, fwupd_security_attr_get_appstream_id(attr));
		json_builder_begin_object(builder);
		fwupd_security_attr_to_json(attr, builder);
		json_builder_end_object(builder);

	}
	json_builder_end_object(builder);
	json_builder_end_object(builder);
}


void
fu_security_attrs_json_to_hashtable(GHashTable *last_security_hash, gchar *json_str, GError **error)
{
	/**
	 *    
   2   JsonParser *parser = json_parser_new ();
   3   json_parser_load_from_data (parser, str, -1, NULL);
   4 
   5   JsonReader *reader = json_reader_new (json_parser_get_root (parser));
   6 
   7   json_reader_read_member (reader, "url");
   8   const char *url = json_reader_get_string_value (reader);
   9   json_reader_end_member (reader);
  10 
  11   json_reader_read_member (reader, "size");
  12   json_reader_read_element (reader, 0);
  13   int width = json_reader_get_int_value (reader);
  14   json_reader_end_element (reader);
  15   json_reader_read_element (reader, 1);
  16   int height = json_reader_get_int_value (reader);
  17   json_reader_end_element (reader);
  18   json_reader_end_member (reader);
  19 
  20   g_object_unref (reader);
  21   g_object_unref (parser);
	 */

	/**
	 *  {
        	"AppstreamId" : "org.fwupd.hsi.IntelDci.Enabled",
        	"HsiLevel" : 1,
        	"HsiResult" : "not-enabled",
        	"Name" : "Intel DCI debugger",
       		 "Plugin" : "msr",
        	"Uri" : "https://fwupd.github.io/hsi.html#org.fwupd.hsi.IntelDci.Enabled",
      		"Flags" : [
        	"success"
        	]
      		},
	 * 
	 */


	g_autoptr(JsonParser) parser = json_parser_new ();
	GHashTable *tmp_hash = NULL;
	JsonArray *security_attrs = NULL;
	JsonArray *flags = NULL;
	json_parser_load_from_data (parser, json_str, -1, NULL);

	JsonNode *json_root = json_parser_get_root(parser);
	JsonObject *json_obj = json_node_get_object(json_root);
	security_attrs = json_object_get_array_member(json_obj, "SecurityAttributes");

	g_warning("%s",json_str);
	for (guint i = 0; i < json_array_get_length(security_attrs); i++) {
		tmp_hash = g_hash_table_new(g_str_hash, g_str_equal);
                JsonObject *related_item;
		related_item = json_array_get_object_element(security_attrs, i);
		const gchar *app_stream_id = json_object_get_string_member(related_item, "AppstreamId");
		const gint hsi_level = json_object_get_int_member(related_item, "HsiLevel");
		const gchar *hsi_result = json_object_get_string_member(related_item, "HsiResult");
		const gchar *dev_name = json_object_get_string_member(related_item, "Name");
		const gchar *related_plugin = json_object_get_string_member(related_item, "Plugin");
		const gchar *uri = json_object_get_string_member(related_item, "Uri");
		
		g_hash_table_insert(tmp_hash, "hsi_level", &hsi_level);
		g_hash_table_insert(tmp_hash, "hsi_result", hsi_result);
		g_warning("%s / %d / %s / %s / %s / %s", app_stream_id, hsi_level, hsi_result, dev_name, related_plugin, uri);
		
		if (json_object_has_member(related_item, "Flags") == TRUE) {
			flags = json_object_get_array_member(related_item, "Flags");
			if (flags != NULL) {
				for (guint x = 0; x < json_array_get_length(flags); x++) {
					JsonNode *tmp_node = json_array_get_element(flags, x);
					g_warning("Flags are %s", json_node_get_string(tmp_node));
				}
				
			}
		}
		g_hash_table_insert(last_security_hash, app_stream_id, tmp_hash);
        }
	
}

gint
fu_security_parse_hsi(const gchar *hsi)
{
	gint ret = 0;
	g_autofree char *tmp_str;
	gchar *tail = NULL;
	tmp_str = g_strdup(hsi);
	tmp_str = tmp_str + 4;
	tail = g_strrstr(tmp_str, "!");
	ret = g_ascii_strtoll(tmp_str, tail, 10); 
	g_warning("HSI to int is %d", ret);
	return ret;
}

gint
fu_security_attrs_compare_hsi_score(const guint previous_hsi, const guint current_hsi)
{
	g_warning("Last HSI %d Current HSI %d", previous_hsi, current_hsi);

	if (current_hsi > previous_hsi)
		return 1;
	else if (current_hsi < previous_hsi)
		return -1;
	else
		return 0;
}

static gboolean
fu_security_attr_deep_object_compare(FwupdSecurityAttr *attr, JsonObject *json_obj)
{
	/* 1. HSI comparison */
	if(fwupd_security_attr_get_level(attr) == json_object_get_int_member(json_obj, FWUPD_RESULT_KEY_HSI_LEVEL)) {
		g_warning("Same level");
		return TRUE;
	}
	
}


void
fu_security_attrs_diff_hsi_reason(FuSecurityAttrs *attrs, const gchar *last_hsi_detail)
{
	g_autoptr(GPtrArray) items = NULL;
	
	
	g_autoptr(JsonParser) parser = json_parser_new ();;

	json_parser_load_from_data (parser, last_hsi_detail, -1, NULL);
	JsonNode *json_root = json_parser_get_root(parser);
	JsonObject *json_obj = json_node_get_object(json_root);
	JsonObject *previous_security_attrs = json_object_get_object_member(json_obj, "SecurityAttributes");


	items = fu_security_attrs_get_all(attrs);
	for (guint i = 0; i < items->len; i++) {
		FwupdSecurityAttr *attr = g_ptr_array_index(items, i);
		g_warning("%s", fwupd_security_attr_get_appstream_id(attr));
		if(json_object_has_member(previous_security_attrs, fwupd_security_attr_get_appstream_id(attr)) == TRUE) {
			/* Hit */
			g_warning("Hit!");

			/* Object comparison */
			fu_security_attr_deep_object_compare(attr, json_object_get_object_member(previous_security_attrs, fwupd_security_attr_get_appstream_id(attr)));
		
		}else {
			/* Miss- A new AppStreamID */

		}
	}

}

