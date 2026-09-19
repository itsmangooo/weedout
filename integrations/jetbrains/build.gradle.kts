plugins {
    java
    id("org.jetbrains.intellij.platform") version "2.19.0"
}

group = "dev.weedout"
version = "0.1.0"

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform { intellijIdea("2024.3.6") }
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
    testRuntimeOnly("junit:junit:4.13.2")
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java { toolchain { languageVersion = JavaLanguageVersion.of(17) } }
tasks.withType<JavaCompile>().configureEach { options.encoding = "UTF-8" }

intellijPlatform {
    pluginConfiguration {
        name = "Weedout"
        ideaVersion { sinceBuild = "243" }
    }
}

tasks.test { useJUnitPlatform() }
