/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package androidx.compose.material.icons.filled

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.materialIcon
import androidx.compose.material.icons.materialPath
import androidx.compose.ui.graphics.vector.ImageVector

public val Icons.Filled.Copyright: ImageVector
    get() {
        if (_copyright != null) {
            return _copyright!!
        }
        _copyright = materialIcon(name = "Filled.Copyright") {
            materialPath {
                moveTo(11.88f, 9.14f)
                curveToRelative(1.28f, 0.06f, 1.61f, 1.15f, 1.63f, 1.66f)
                horizontalLineToRelative(1.79f)
                curveToRelative(-0.08f, -1.98f, -1.49f, -3.19f, -3.45f, -3.19f)
                curveTo(9.64f, 7.61f, 8.0f, 9.0f, 8.0f, 12.14f)
                curveToRelative(0.0f, 1.94f, 0.93f, 4.24f, 3.84f, 4.24f)
                curveToRelative(2.22f, 0.0f, 3.41f, -1.65f, 3.44f, -2.95f)
                horizontalLineToRelative(-1.79f)
                curveToRelative(-0.03f, 0.59f, -0.45f, 1.38f, -1.63f, 1.44f)
                curveTo(10.55f, 14.83f, 10.0f, 13.81f, 10.0f, 12.14f)
                curveTo(10.0f, 9.25f, 11.28f, 9.16f, 11.88f, 9.14f)
                close()
                moveTo(12.0f, 2.0f)
                curveTo(6.48f, 2.0f, 2.0f, 6.48f, 2.0f, 12.0f)
                reflectiveCurveToRelative(4.48f, 10.0f, 10.0f, 10.0f)
                reflectiveCurveToRelative(10.0f, -4.48f, 10.0f, -10.0f)
                reflectiveCurveTo(17.52f, 2.0f, 12.0f, 2.0f)
                close()
                moveTo(12.0f, 20.0f)
                curveToRelative(-4.41f, 0.0f, -8.0f, -3.59f, -8.0f, -8.0f)
                reflectiveCurveToRelative(3.59f, -8.0f, 8.0f, -8.0f)
                reflectiveCurveToRelative(8.0f, 3.59f, 8.0f, 8.0f)
                reflectiveCurveTo(16.41f, 20.0f, 12.0f, 20.0f)
                close()
            }
        }
        return _copyright!!
    }

private var _copyright: ImageVector? = null
