package com.sukisu.ultra.ui.activity.util

import androidx.compose.animation.*
import androidx.compose.animation.core.tween
import androidx.navigation.NavBackStackEntry
import com.ramcosta.composedestinations.animations.NavHostAnimatedDestinationStyle
import com.ramcosta.composedestinations.generated.destinations.ExecuteModuleActionScreenDestination
import com.sukisu.ultra.ui.screen.BottomBarDestination

object NavigationUtils {

    /**
     * 获取底部导航栏路由集合
     */
    fun getBottomBarRoutes(): Set<String> {
        return BottomBarDestination.entries.map { it.direction.route }.toSet()
    }

    /**
     * 判断是否应该显示底部导航栏
     */
    fun shouldShowBottomBar(currentRoute: String?): Boolean {
        return when (currentRoute) {
            ExecuteModuleActionScreenDestination.route -> false
            else -> true
        }
    }

    /**
     * 创建导航动画样式
     */
    fun createNavHostAnimations(): NavHostAnimatedDestinationStyle {
        val bottomBarRoutes = getBottomBarRoutes()

        return object : NavHostAnimatedDestinationStyle() {
            override val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
                // If the target is a detail page (not a bottom navigation page), slide in from the right
                if (targetState.destination.route !in bottomBarRoutes) {
                    slideInHorizontally(initialOffsetX = { it })
                } else {
                    // Otherwise (switching between bottom navigation pages), use fade in
                    fadeIn(animationSpec = tween(340))
                }
            }

            override val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
                // If navigating from the home page (bottom navigation page) to a detail page, slide out to the left
                if (initialState.destination.route in bottomBarRoutes && targetState.destination.route !in bottomBarRoutes) {
                    slideOutHorizontally(targetOffsetX = { -it / 4 }) + fadeOut()
                } else {
                    // Otherwise (switching between bottom navigation pages), use fade out
                    fadeOut(animationSpec = tween(340))
                }
            }

            override val popEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
                // If returning to the home page (bottom navigation page), slide in from the left
                if (targetState.destination.route in bottomBarRoutes) {
                    slideInHorizontally(initialOffsetX = { -it / 4 }) + fadeIn()
                } else {
                    // Otherwise (e.g., returning between multiple detail pages), use default fade in
                    fadeIn(animationSpec = tween(340))
                }
            }

            override val popExitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
                // If returning from a detail page (not a bottom navigation page), scale down and fade out
                if (initialState.destination.route !in bottomBarRoutes) {
                    scaleOut(targetScale = 0.9f) + fadeOut()
                } else {
                    // Otherwise, use default fade out
                    fadeOut(animationSpec = tween(340))
                }
            }
        }
    }
}