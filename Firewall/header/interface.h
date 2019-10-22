#pragma once

#include <dirent.h>

dirent *get_interface_dir_list();

bool get_interface_ip_address(char *, ip_address *);
void get_interface_mac_address(char *, mac_address *);