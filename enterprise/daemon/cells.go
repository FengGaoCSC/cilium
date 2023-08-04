//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package daemon

//  Note: if you reading this, then it is likely that you hit a conflict while
//  backporting a commit from main-ce. The enterprise agent was not bootstrapped
//  in v1.14-ce. Modifications to this file should be applied directly to
//  daemon/cmd/enterprise_cells.go, avoiding to introduce circular dependencies.
