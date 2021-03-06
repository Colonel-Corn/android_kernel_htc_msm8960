/*
 * Author: Chad Froebel <chadfroebel@gmail.com>
 *
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

/*
 * Possible values for "force_fast_charge" are :
 *
 *   0 - disabled (default)
 *   1 - substitute AC to USB unconditional
 *   2 - substitute AC to USB only if no USB peripheral is detected
 *
 * Possible values for "USB_peripheral_detected" are :
 *
 *   0 - No USB accessory currently attached (default)
 *   1 - USB accessory currently attached
 *
 * Possible values for "USB_porttype_detected" are :
 *
 *   0 - invalid USB port
 *   1 - standard downstream port
 *   2 - dedicated charging port
 *   3 - charging downstream port
 *   4 - accessory charger adapter A
 *   5 - accessory charger adapter B
 *   6 - accessory charger adapter C
 *   7 - accessory charger adapter dock
 *  10 - nothing attached (default)
 *
 * Possible values for "is_fast_charge_forced" are :
 *
 *   0 - fast charging is currently not forced
 *   1 - fast charging is currently forced
 *
 * Possible values for "current_charge_mode" are :
 *
 *   0 - Discharging
 *   1 - AC
 *   2 - USB
 */

#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/fastchg.h>

int force_fast_charge;
int USB_peripheral_detected;
int USB_porttype_detected;
int is_fast_charge_forced;
int current_charge_mode;

/* sysfs interface for "force_fast_charge" */
static ssize_t force_fast_charge_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
return sprintf(buf, "%d\n", force_fast_charge);
}

static ssize_t force_fast_charge_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{

int new_force_fast_charge;

sscanf(buf, "%du", &new_force_fast_charge);

if (new_force_fast_charge >= FAST_CHARGE_DISABLED && new_force_fast_charge <= FAST_CHARGE_FORCE_AC_IF_NO_USB) {

	/* update only if valid value provided */
	force_fast_charge = new_force_fast_charge;

}

return count;
}

static struct kobj_attribute force_fast_charge_attribute =
__ATTR(force_fast_charge, 0666, force_fast_charge_show, force_fast_charge_store);

static struct attribute *force_fast_charge_attrs[] = {
&force_fast_charge_attribute.attr,
NULL,
};

static struct attribute_group force_fast_charge_attr_group = {
.attrs = force_fast_charge_attrs,
};

/* sysfs interface for "USB_peripheral_detected" */
static ssize_t USB_peripheral_detected_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
return sprintf(buf, "%d\n", USB_peripheral_detected);
}

static ssize_t USB_peripheral_detected_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
/* no user change allowed */
return count;
}

static struct kobj_attribute USB_peripheral_detected_attribute =
__ATTR(USB_peripheral_detected, 0444, USB_peripheral_detected_show, USB_peripheral_detected_store);

static struct attribute *USB_peripheral_detected_attrs[] = {
&USB_peripheral_detected_attribute.attr,
NULL,
};

static struct attribute_group USB_peripheral_detected_attr_group = {
.attrs = USB_peripheral_detected_attrs,
};

/* sysfs interface for "USB_porttype_detected" */
static ssize_t USB_porttype_detected_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	switch (USB_porttype_detected) {
		case USB_INVALID_DETECTED:	return sprintf(buf, "Invalid Port\n");
		case USB_SDP_DETECTED:		return sprintf(buf, "Standard Downstream Port\n");
		case USB_DCP_DETECTED:		return sprintf(buf, "Dedicated Charging Port\n");
		case USB_CDP_DETECTED:		return sprintf(buf, "Charging Downstream Port\n");
		case USB_ACA_A_DETECTED:	return sprintf(buf, "Accessory Charger Adapter A\n");
		case USB_ACA_B_DETECTED:	return sprintf(buf, "Accessory Charger Adapter B\n");
		case USB_ACA_C_DETECTED:	return sprintf(buf, "Accessory Charger Adapter C\n");
		case USB_ACA_DOCK_DETECTED:	return sprintf(buf, "Accessory Charger Adapter Dock\n");
		case NO_USB_DETECTED:		return sprintf(buf, "No Port\n");
		default:			return sprintf(buf, "something went wrong\n");
	}
}

static ssize_t USB_porttype_detected_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
/* no user change allowed */
return count;
}

static struct kobj_attribute USB_porttype_detected_attribute =
__ATTR(USB_porttype_detected, 0444, USB_porttype_detected_show, USB_porttype_detected_store);

static struct attribute *USB_porttype_detected_attrs[] = {
&USB_porttype_detected_attribute.attr,
NULL,
};

static struct attribute_group USB_porttype_detected_attr_group = {
.attrs = USB_porttype_detected_attrs,
};

/* sysfs interface for "is_fast_charge_forced" */
static ssize_t is_fast_charge_forced_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	switch (is_fast_charge_forced) {
		case FAST_CHARGE_NOT_FORCED:	return sprintf(buf, "No\n");
		case FAST_CHARGE_FORCED:	return sprintf(buf, "Yes\n");
		default:			return sprintf(buf, "something went wrong\n");
	}
}

static ssize_t is_fast_charge_forced_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
/* no user change allowed */
return count;
}

static struct kobj_attribute is_fast_charge_forced_attribute =
__ATTR(is_fast_charge_forced, 0444, is_fast_charge_forced_show, is_fast_charge_forced_store);

static struct attribute *is_fast_charge_forced_attrs[] = {
&is_fast_charge_forced_attribute.attr,
NULL,
};

static struct attribute_group is_fast_charge_forced_attr_group = {
.attrs = is_fast_charge_forced_attrs,
};


/* sysfs interface for "current_charge_mode" */
static ssize_t current_charge_mode_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	switch (current_charge_mode) {
		case CURRENT_CHARGE_MODE_DISCHARGING:	return sprintf(buf, "Discharging\n");
		case CURRENT_CHARGE_MODE_AC:		return sprintf(buf, "AC\n");
		case CURRENT_CHARGE_MODE_USB:		return sprintf(buf, "USB\n");
		default:				return sprintf(buf, "something went wrong\n");
	}
}

static ssize_t current_charge_mode_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
/* no user change allowed */
return count;
}

static struct kobj_attribute current_charge_mode_attribute =
__ATTR(current_charge_mode, 0444, current_charge_mode_show, current_charge_mode_store);

static struct attribute *current_charge_mode_attrs[] = {
&current_charge_mode_attribute.attr,
NULL,
};

static struct attribute_group current_charge_mode_attr_group = {
.attrs = current_charge_mode_attrs,
};

/* Initialize fast charge sysfs folder */
static struct kobject *force_fast_charge_kobj;

int force_fast_charge_init(void)
{
	int force_fast_charge_retval;
	int USB_peripheral_detected_retval;
	int USB_porttype_detected_retval;
	int is_fast_charge_forced_retval;
	int current_charge_mode_retval;

	force_fast_charge = FAST_CHARGE_DISABLED; /* Forced fast charge disabled by default */
	USB_peripheral_detected = USB_ACC_NOT_DETECTED; /* Consider no USB accessory detected so far */
	USB_porttype_detected = NO_USB_DETECTED; /* Consider no USB port is yet detected */
	is_fast_charge_forced = FAST_CHARGE_NOT_FORCED; /* Consider fast charge is not forced at start */
	current_charge_mode = CURRENT_CHARGE_MODE_DISCHARGING; /* Consider we are discharging at start */

        force_fast_charge_kobj = kobject_create_and_add("fast_charge", kernel_kobj);
        if (!force_fast_charge_kobj) {
                return -ENOMEM;
        }
        force_fast_charge_retval = sysfs_create_group(force_fast_charge_kobj, &force_fast_charge_attr_group);
        USB_peripheral_detected_retval = sysfs_create_group(force_fast_charge_kobj, &USB_peripheral_detected_attr_group);
        USB_porttype_detected_retval = sysfs_create_group(force_fast_charge_kobj, &USB_porttype_detected_attr_group);
        is_fast_charge_forced_retval = sysfs_create_group(force_fast_charge_kobj, &is_fast_charge_forced_attr_group);
        current_charge_mode_retval = sysfs_create_group(force_fast_charge_kobj, &current_charge_mode_attr_group);
        if (force_fast_charge_retval && USB_peripheral_detected_retval && USB_porttype_detected_retval && is_fast_charge_forced_retval && current_charge_mode_retval)
                kobject_put(force_fast_charge_kobj);
        return (force_fast_charge_retval && USB_peripheral_detected_retval && USB_porttype_detected_retval && is_fast_charge_forced_retval && current_charge_mode_retval);
}
/* end sysfs interface */

void force_fast_charge_exit(void)
{
	kobject_put(force_fast_charge_kobj);
}

module_init(force_fast_charge_init);
module_exit(force_fast_charge_exit);
