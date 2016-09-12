/*
Copyright (C) 2013-2014 Draios inc.

This file is part of sysdig.

sysdig is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License version 2 as
published by the Free Software Foundation.

sysdig is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with sysdig.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <functional>

/** @defgroup state State management 
 *  @{
 */

/*!
	\brief An IPv4 tuple. 
*/
typedef union _ipv4tuple
{
	struct 
	{
		uint32_t m_sip; ///< Source (i.e. client) address. 
		uint32_t m_dip; ///< Destination (i.e. server) address.
		uint16_t m_sport; ///< Source (i.e. client) port.
		uint16_t m_dport; ///< Destination (i.e. server) port.
	};
	uint8_t m_all[12]; ///< The fields as a raw array ob bytes. Used for hashing.
} ipv4tuple;


inline bool operator==(ipv4tuple a, ipv4tuple b)
{
	return (a.m_sip == b.m_sip &&
			a.m_dip == b.m_dip &&
			a.m_sport == b.m_sport &&
			a.m_dport == b.m_dport);
}


struct ipv4tupleHash {
	size_t operator()(const ipv4tuple &tuple) const
	{
		const unsigned char* p = reinterpret_cast<const unsigned char*>( &tuple );
		size_t h = 2166136261;

		for (unsigned int i = 0; i < sizeof(tuple); ++i)
			h = (h * 16777619) ^ p[i];

		return h;
	}
};


/*!
	\brief An IPv6 tuple. 
*/
typedef union _ipv6tuple
{
	struct
	{
		uint32_t m_sip[4]; ///< source (i.e. client) address.
		uint32_t m_dip[4]; ///< destination (i.e. server) address.
		uint16_t m_sport; ///< source (i.e. client) port.
		uint16_t m_dport; ///< destination (i.e. server) port.
		uint8_t m_l4proto; ///< Layer 4 protocol (e.g. TCP, UDP...)
	} m_fields;
	uint8_t m_all[37]; ///< The fields as a raw array ob bytes. Used for hasing.
} ipv6tuple;


/*@}*/
