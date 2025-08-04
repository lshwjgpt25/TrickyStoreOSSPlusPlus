/*
 * Copyright 2025 Dakkshesh <beakthoven@gmail.com>
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

package android.os;

public class ServiceManager {
    public static IBinder getService(String name) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static void addService(String name, IBinder binder) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static IBinder checkService(String name) {
        throw new UnsupportedOperationException("STUB!");
    }

    public static String[] listServices() {
        throw new UnsupportedOperationException("STUB!");
    }
}
