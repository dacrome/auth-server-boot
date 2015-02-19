/*
 * Produktname:       POLARIS
 * Projektname:       Interaktiver Funkstreifenwagen der Polizei Brandenburg
 * Kurzbeschreibung:  Universelle mobile Kommunikationsplattform für BOS Einsatzkräfte (Polizei, Feuerwehr etc.)
 * Firmenname:        Polizei Brandenburg, ZDPOL Bereich IT
 * eMail :            mike.peter@polizei.brandenburg.de
 *
 * Copyright (C) 2014 Polizei Brandenburg, ZDPOL Bereich IT
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 */

package org.osiam.auth_server;

public class ServiceInfo {

    private String name;
    private String version;

    public ServiceInfo(String name, String version) {
        this.name = name;
        this.version = version;
    }

    public String getName() {
        return name;
    }

    public String getVersion() {
        return version;
    }
}
