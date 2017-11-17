#!/bin/sh
#
# librle implements the Return Link Encapsulation (RLE) protocol
#
# Copyright (C) 2017, Thales Alenia Space France - All Rights Reserved
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; If not, see <https://www.gnu.org/licenses/>.
#

#
# @file   coding_style_check.sh
# @brief  Check coding style of source code
# @author Didier Barvaux
# @date   2017, June
# @copyright
#   Copyright (C) 2017, Thales Alenia Space France - All Rights Reserved
#


script_dir=$( dirname "$0" )
sources_dir=$1
work_dir=$2
do_apply=$3

# check script usage
if [ -z "${sources_dir}" ] || [ -z "${work_dir}" ] ; then
	echo "usage: $0 <sources_dir> <work_dir>" >&2
	exit 2
fi

# check that uncrustify is new enough to have the --check option
uncrustify --help | grep -q -- --check
if [ $? -ne 0 ] ; then
	echo "uncrustify is too old, the --check option is not available" >&2
	exit 2
fi

# search for source files
find ${sources_dir} -name *.h -or -name *.c | \
	grep -v '\/deps\/' | \
	grep -v "^${work_dir}" \
	> ${work_dir}/coding_style.list

if [ "${do_apply}" != "apply" ] ; then
	# ask uncrustify to check for coding style on every source file
	uncrustify -q \
		-c ${script_dir}/uncrustify.cfg \
		-F ${work_dir}/coding_style.list \
		--check
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "coding style is not fully respected, go fix your code (code ${ret})" >&2
		exit ${ret}
	fi
else
	# ask uncrustify to apply coding style on every source file
	uncrustify -q \
		-c ${script_dir}/uncrustify.cfg \
		-F ${work_dir}/coding_style.list \
		--replace --no-backup --mtime
	ret=$?
	if [ ${ret} -ne 0 ] ; then
		echo "coding style was not applied correctly (code ${ret})" >&2
		exit ${ret}
	fi
	echo "coding style was applied on every source file"
fi

exit 0

