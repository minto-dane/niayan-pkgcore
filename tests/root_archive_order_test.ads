-- SPDX-License-Identifier: BSD-3-Clause
with MC_Types; use MC_Types;
with MC_FS; with MC_Store;
package Root_Archive_Order_Test is
   procedure Run (Store : in out MC_Store.Store; Media : MC_FS.Root; Deadline : Counter);
end Root_Archive_Order_Test;
