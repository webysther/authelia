import { getEmbeddedVariable } from "@utils/Configuration";

export function getBasePath() {
    return getEmbeddedVariable("basepath");
}

export function getBasePathSlash() {
    const basePath = getBasePath();

    return basePath === "" ? basePath : basePath + "/";
}
