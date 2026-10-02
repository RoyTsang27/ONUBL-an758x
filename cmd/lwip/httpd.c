// SPDX-License-Identifier: GPL-2.0+

#include <command.h>
#include <net/httpd.h>
#include <string.h>

static int do_httpd(struct cmd_tbl *cmdtp, int flag, int argc,
		    char *const argv[])
{
	bool with_dhcp = false;
	bool privileged = true;
	int i;

	if (argc > 3)
		return CMD_RET_USAGE;
	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "dhcp") && !with_dhcp)
			with_dhcp = true;
		else if (!strcmp(argv[i], "safe") && privileged)
			privileged = false;
		else
			return CMD_RET_USAGE;
	}

	if (uboot_httpd_is_running())
		return CMD_RET_SUCCESS;

	return uboot_httpd_start_mode(with_dhcp, privileged) ?
		CMD_RET_FAILURE : CMD_RET_SUCCESS;
}

U_BOOT_CMD(httpd, 3, 0, do_httpd,
	   "start the browser management and recovery service",
	   "[dhcp] [safe]\n"
	   "    - serve HTTP on the recovery address; 'dhcp' also leases one address\n"
	   "      'safe' restricts automatic recovery to info, boot retry and reset");
