const QUERY_NAMES = {
  "cwe-022wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-22",
  },
  "cwe-022wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-22 (CodeQL)",
  },
  "cwe-078wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-78",
  },
  "cwe-078wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-78 (CodeQL)",
  },
  "cwe-079wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-79",
  },
  "cwe-079wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-79 (CodeQL)",
  },
  "cwe-094wLLM": {
    "type": "cwe-query",
    "display_name": "CWE-94",
  },
  "cwe-094wCodeQL": {
    "type": "cwe-query",
    "display_name": "CWE-94 (CodeQL)",
  },
}

/**
 * Get the URL search parameter `cwe`
 * @returns string | null
 */
function getQueriedCWEFromURL() {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("cwe")) {
    return parseInt(searchParams.get("cwe"));
  } else {
    return null;
  }
}

/**
 * Get the URL search parameter `cve`
 * @returns string | null
 */
function getQueriedCVEFromURL() {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("cve")) {
    return searchParams.get("cve");
  } else {
    return null;
  }
}

/**
 * Get the URL search parameter `tab`
 * @returns string | null
 */
function getQueriedTabFromURL() {
  const searchParams = new URLSearchParams(window.location.search);
  if (searchParams.has("tab")) {
    return searchParams.get("tab");
  } else {
    return null;
  }
}

function generateHrefURL(cwe, cve, tab) {
  const searchParams = new URLSearchParams(window.location.search);
  let queryParams = [];
  if (cwe != null) {
    if (cwe != "") {
      queryParams.push(`cwe=${cwe}`);
    }
  } else if (searchParams.has("cwe")) {
    queryParams.push(`cwe=${searchParams.get("cwe")}`)
  }
  if (cve != null) {
    if (cve != "") {
      queryParams.push(`cve=${cve}`);
    }
  } else if (searchParams.has("cve")) {
    queryParams.push(`cve=${searchParams.get("cve")}`)
  }
  if (tab != null && tab != "") {
    queryParams.push(`tab=${tab}`);
  }
  if (queryParams.length > 0) {
    return VIEWER_HTML_DIR + "?" + queryParams.join("&");
  } else {
    return VIEWER_HTML_DIR;
  }
}

function getScrollParent(node) {
  const regex = /(auto|scroll)/;
  const parents = (_node, ps) => {
    if (_node.parentNode === null) { return ps; }
    return parents(_node.parentNode, ps.concat([_node]));
  };
  const style = (_node, prop) => getComputedStyle(_node, null).getPropertyValue(prop);
  const overflow = _node => style(_node, 'overflow') + style(_node, 'overflow-y') + style(_node, 'overflow-x');
  const scroll = _node => regex.test(overflow(_node));
  const scrollParent = (_node) => {
    if (!(_node instanceof HTMLElement || _node instanceof SVGElement)) {
      return;
    }
    const ps = parents(_node.parentNode, []);
    for (let i = 0; i < ps.length; i += 1) {
      if (scroll(ps[i])) {
        return ps[i];
      }
    }
    return document.scrollingElement || document.documentElement;
  };
  return scrollParent(node);
};

function expandExpandableText(elem, length) {
  let fullText = $(elem).children(".full").text();
  let showLess = `<a href="#" onclick="shrinkExpandableText(this, ${length})" style="text-decoration: none"><br />(Show less)<span class="full" hidden="hidden">${fullText}</span></a>`;
  let parent = $(elem).parent();
  parent.html(fullText + showLess);
}

function shrinkExpandableText(elem, length) {
  let fullText = $(elem).children(".full").text();
  let parent = $(elem).parent();
  let top = parent.offset().top;
  parent.html(expandableTextToHTML(fullText, length));
  $(getScrollParent(parent[0])).animate({ scrollTop: top }, 50);
}

function expandableTextToHTML(text, length) {
  if (text.length > length) {
    let showMore = `... <a href="#" onclick="expandExpandableText(this, ${length})" style="text-decoration: none">(Show more)<span class="full" hidden="hidden">${text}</span></a>`;
    return text.substring(0, length).trim() + showMore;
  } else {
    return text;
  }
}

function renderCWEBadge(cweId) {
  return `<span class="badge text-bg-secondary" style="margin-left: 3px">${cweId}</span>`
}

function renderSidebarItem(cveRow, index) {
  let queriedCveId = getQueriedCVEFromURL();
  let cve = cveRow["cve_id"];
  let project = cveRow["project_slug"];
  let [author, package] = project.split("_CVE-")[0].split("__");
  let tag = cveRow["github_tag"];
  let active = cve == queriedCveId ? "active" : "";
  let cweBadges = cveRow["cwe_id"].split(";").map(renderCWEBadge).join("");
  return `
    <a id="sidebar-item-${cve}" href="${generateHrefURL(null, cve)}" class="list-group-item list-group-item-action ${active} py-3 lh-tight" aria-current="true">
      <div class="d-flex w-100 align-items-center justify-content-between">
        <strong class="mb-1">${cveRow['cve_id']}</strong>
        <small>${cweBadges}</small>
      </div>
      <div class="col-10 mb-1 small">${author} / ${package} / ${tag}</div>
    </a>
  `;
}

function renderSidebar(projectInfo) {
  $("#sidebar-cwe-list").html(projectInfo.filter((cveRow) => {
    let cve = cveRow["cve_id"];
    if (cve == "") {
      return false;
    }

    let commits = cveRow["fix_commit_ids"];
    if (commits == "") {
      return false;
    }

    let queriedCweId = getQueriedCWEFromURL();
    if (queriedCweId) {
      if (!cveRow["cwe_id"]) {
        return false;
      }
      let cwes = cveRow["cwe_id"].split(";");
      if (cwes.indexOf(`CWE-${queriedCweId}`) < 0) {
        return false;
      }
    }

    if (cveRow["id"] == "") {
      return false;
    }

    return true;
  }).map((cveRow, index) => {
    return renderSidebarItem(cveRow, index);
  }).join(""));

  let cve = getQueriedCVEFromURL();
  if (cve != null && $(`#sidebar-item-${cve}`)[0]) {
    $("#sidebar-cwe-list").animate({
      scrollTop: $(`#sidebar-item-${cve}`).offset().top - $("#sidebar-header").outerHeight()
    }, 50);
  }

  let cwe = getQueriedCWEFromURL();
  if (cwe != null) {
    $(`#sidebar-filter-${cwe}-button`).addClass("active");
  } else {
    $("#sidebar-filter-all-button").addClass("active");
  }

  $("#sidebar-filter-all-button").attr("href", generateHrefURL("", cve));
  $("#sidebar-filter-22-button").attr("href", generateHrefURL("22", cve));
  $("#sidebar-filter-78-button").attr("href", generateHrefURL("78", cve));
  $("#sidebar-filter-79-button").attr("href", generateHrefURL("79", cve));
  $("#sidebar-filter-94-button").attr("href", generateHrefURL("94", cve));
}

function queryNVDDescription(cveId, callback) {
  fetchJSON(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, (data) => {
    if (data && data["vulnerabilities"].length > 0) {
      let vul = data["vulnerabilities"][0];
      let descriptions = vul["cve"]["descriptions"]
        .filter((desc) => desc["lang"] == "en")
        .map((desc) => `${desc["value"]}`).join("<br />");
      callback(descriptions);
    } else {
      callback("Vulnerability not found in NVD database")
    }
  })
}

function renderCommit(cveRow, commitId) {
  let commitLink = `https://github.com/${cveRow['github_username']}/${cveRow['github_repository_name']}/commit/${commitId}`;
  return `
    <a target="_blank" href="${commitLink}" style="text-decoration: none;">
      <span class="badge text-bg-primary" style="margin-left: 3px">${commitId}</span>
    </a>
  `;
}

function renderFixedCommits(cveRow, commits) {
  $("#fixing-commits").html(commits.map(commitId => renderCommit(cveRow, commitId)).join(""));
}

function renderFixedMethods(cve, githubAuthor, githubProject, fixedMethods) {
  let locationsMap = {};
  let relevantFixedMethods = fixedMethods[cve]["locations"];
  for (let i in relevantFixedMethods) {
    let row = relevantFixedMethods[i];
    if (row["file"].indexOf("src/test/") == -1) {
      let parts = row["file"].split("/");
      let fileName = parts[parts.length - 1].split(".java")[0] + " : " + row["method"];
      let href = `https://github.com/${githubAuthor}/${githubProject}/blob/${row["commit"]}/${row["file"]}`;
      locationsMap[fileName] = href;
    }
  }

  let locations = [];
  for (let key in locationsMap) {
    locations.push({
      file: key,
      href: locationsMap[key],
    });
  }

  $("#fixing-locs").html(locations.map(({ file, href }) => {
    return `
      <a target="_blank" href="${href}" style="text-decoration: none;">
        <span class="badge rounded-pill text-bg-primary" style="margin-left: 3px">${file}</span>
      </a>
    `;
  }).join(""));
}

function loadCommitsTabContent(cveRow) {
  let commits = cveRow["fix_commit_ids"].split(";");
  let githubAuthor = cveRow["github_username"];
  let githubProject = cveRow["github_repository_name"];
  fold(commits, "", (commitId, _, html, callback) => {
    let fileName = `https://api.github.com/repos/${githubAuthor}/${githubProject}/commits/${commitId}`;
    fetchJSON(fileName, (commitData) => {
      if (!commitData) {
        return callback(html);
      }
      commitData["files"].forEach((fileJSON) => {
        if (fileJSON["filename"].indexOf(".java") == fileJSON["filename"].length - 5) {
          let patch = fileJSON["patch"]
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
          let patchLines = patch.split("\n").map((line) => {
            if (line[0] == "-") {
              return `<div class="line remove">${line}</div>`;
            } else if (line[0] == "+") {
              return `<div class="line add">${line}</div>`;
            } else {
              return `<div class="line">${line}</div>`;
            }
          });
          let changeFileHTML = `
            <div class="diff-file">
              <div class="d-flex highlight-toolbar ps-3 pe-2 py-1">
                <a target="_blank" href="${commitData["html_url"]}">${commitData["sha"].substring(0, 12)}</a>
                &nbsp:&nbsp
                <a target="_blank" href="${fileJSON["blob_url"]}">${fileJSON["filename"]}</a>
              </div>
              <div class="d-flex highlight-toolbar ps-3 pe-2 py-1 border rounded bg-body-tertiary">
                <pre>${patchLines.join("")}</pre>
              </div>
            </div>`;
          html += changeFileHTML;
        } else {
          let changeFileHTML = `
            <div class="diff-file">
              <div>
                <a target="_blank" href="${commitData["html_url"]}">${commitData["sha"].substring(0, 12)}</a>
                &nbsp:&nbsp
                <a target="_blank" href="${fileJSON["blob_url"]}">${fileJSON["filename"]}</a>
              </div>
            </div>`;
          html += changeFileHTML;
        }
      })
      callback(html);
    })
  }, (html) => {
    $("#fix-file-diffs").html(html)
  });
}

const FIX_TAB_CONTENT = `
  <div class="tab-pane fade show active" id="fix" role="tabpanel" aria-labelledby="fix-tab">
    <div id="fix-file-diffs"></div>
  </div>
`;

function folderToElemId(folder) {
  return `${folder["run_id"]}-${folder["query"]}`;
}

function renderCommitTab() {
  let href = generateHrefURL(null, null, "fix");
  let quriedTab = getQueriedTabFromURL()
  let active = (!quriedTab || quriedTab == "fix") ? "active" : "";
  return `
    <li class="nav-item active" role="presentation">
      <a class="nav-link ${active}" href="${href}" id="fix-tab">Commits and Fixes</a>
    </li>
  `;
}

function renderTabs() {
  let fixTab = renderCommitTab();

  // Generate all the tabs
  let allTabs = [fixTab];

  $("#result-tabs").html(allTabs.join(""));
}

function renderCWEQueryTabContent(folder) {
  let folderElemId = folderToElemId(folder);
  return `
    <div class="tab-pane fade" id="${folderElemId}" role="tabpanel" aria-labelledby="${folderElemId}-tab">
      <h6><strong>Quick Access</strong></h6>
      <ul id="${folderElemId}-quick-access" class="pagination" style="flex-wrap: wrap"></ul>
      <h6><strong>Alarms (<span id="${folderElemId}-num-alerts"></span>)</strong></h6>
      <div id="${folderElemId}-alerts"></div>
    </div>
  `;
}

function renderBasicTabContent(folder) {
  switch (QUERY_NAMES[folder["query"]]["type"]) {
    case "cwe-query": return renderCWEQueryTabContent(folder);
    default: return "";
  }
}

function escapeCode(code) {
  if (code) {
    return code
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  } else {
    return "";
  }
}

function getGithubRawURLFromCodeFlowStep(cveRow, step) {
  // https://raw.githubusercontent.com/perwendel/spark/2.5.1/src/main/java/spark/resource/ClassPathResource.java
  let repoURL = cveRow["repository_url"].replace("https://github.com/", "https://raw.githubusercontent.com/");
  let tag = cveRow["github_tag"];
  let relativeFileDir = step["location"]["physicalLocation"]["artifactLocation"]["uri"];
  return `${repoURL}/${tag}/${relativeFileDir}`;
}

function getGithubLocationURLFromCodeFlowStep(cveRow, step) {
  // https://github.com/perwendel/spark/blob/2.5.1/src/main/java/spark/resource/ClassPathResource.java#L51-L55
  let repoURL = cveRow["repository_url"];
  let tag = cveRow["github_tag"];
  let relativeFileDir = step["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = step["location"]["physicalLocation"]["region"]["startLine"];
  return `${repoURL}/blob/${tag}/${relativeFileDir}#L${lineNum}`;
}

function resultSarifCodeFlowStepToHTML(stepId, step, cveRow, isFileLevelMatch, isMethodLevelMatch) {
  let goldLabel = isMethodLevelMatch ? "<span>🥇</span>" : "";
  let silverLabel = isFileLevelMatch ? "<span>🥈</span>" : "";
  let locMessage = escapeCode(step["location"]["message"]["text"]);
  let githubLink = getGithubLocationURLFromCodeFlowStep(cveRow, step)
  return `
    <a href="${githubLink}" target="_blank" class="list-group-item list-group-item-action rounded code-flow-item" style="position: inherit!important;">
      ${silverLabel}${goldLabel}
      <code>${locMessage}</code>
    </a>
  `;
}

function clampText(txt, length) {
  if (txt.length > length) {
    return txt.substring(0, length) + "...";
  } else {
    return txt;
  }
}

function getLocFileLevelLabel(cve_id, loc, fixedMethods) {
  let uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  if (fixedMethods[cve_id]) {
    return fixedMethods[cve_id]["file_level"].indexOf(uri) >= 0;
  } else {
    return false;
  }
}

function getEnclosingItem(uri, lineNum, itemLocs) {
  let item = null;
  let maxItemStartLine = null;
  for (let i = 0; i < itemLocs.length; i++) {
    let currItemLoc = itemLocs[i];
    let currItemFile = currItemLoc["file"];
    let currItemStartLine = parseInt(currItemLoc["start_line"]);
    let currItemEndLine = parseInt(currItemLoc["end_line"]);
    if (currItemFile == uri && currItemStartLine <= lineNum + 1 && currItemEndLine >= lineNum - 1) {
      if (!item || currItemStartLine > maxItemStartLine) {
        item = currItemLoc["name"];
        maxItemStartLine = currItemStartLine;
      }
    }
  }
  return item;
}

function getLocMethodLevelLabel(cve_id, loc, fixedMethods, classLocs, funcLocs) {
  if (!fixedMethods[cve_id]) {
    return false;
  }

  let uri = loc["location"]["physicalLocation"]["artifactLocation"]["uri"];
  let lineNum = loc["location"]["physicalLocation"]["region"]["startLine"];

  let func = getEnclosingItem(uri, lineNum, funcLocs);
  if (!func) { return false; }

  let clazz = getEnclosingItem(uri, lineNum, classLocs);
  if (!clazz) { return false; }

  let location = `${uri}:${clazz}:${func}`;
  return fixedMethods[cve_id]["method_level"].indexOf(location) >= 0;
}

function getCodeFlowFileLevelLabel(cveId, codeFlow, fixedMethods) {
  return codeFlow["threadFlows"][0]["locations"].map((loc) => {
    return getLocFileLevelLabel(cveId, loc, fixedMethods);
  });
}

function getCodeFlowMethodLevelLabel(cveId, codeFlow, fixedMethods, classLocs, funcLocs) {
  return codeFlow["threadFlows"][0]["locations"].map((loc) => {
    return getLocMethodLevelLabel(cveId, loc, fixedMethods, classLocs, funcLocs);
  });
}

function resultSarifCodeFlowToHTML(folder, alarmId, codeFlowId, codeFlow, cveRow, fileLevelLabels, methodLevelLabels) {
  let folderElemId = folderToElemId(folder);

  let steps = codeFlow["threadFlows"][0]["locations"];
  let sourceUrl = getGithubLocationURLFromCodeFlowStep(cveRow, steps[0]);
  let sourceFile = clampText(sourceUrl.split("/").pop().split(".java")[0], 20);
  let sinkUrl = getGithubLocationURLFromCodeFlowStep(cveRow, steps[steps.length - 1]);
  let sinkFile = clampText(sinkUrl.split("/").pop().split(".java")[0], 20);

  let numIntermediateSteps = steps.length;
  let intermediateStepsHTML = steps.map((step, stepId) => {
    let isFileLevelMatch = fileLevelLabels[stepId];
    let isMethodLevelMatch = methodLevelLabels[stepId];
    return resultSarifCodeFlowStepToHTML(stepId, step, cveRow, isFileLevelMatch, isMethodLevelMatch);
  }).join("");

  let isGold = methodLevelLabels.some(v => v);
  let goldLabel = isGold ? "<span>🥇</span>" : "";
  let isSilver = fileLevelLabels.some(v => v);
  let silverLabel = (!isGold && isSilver) ? "<span>🥈</span>" : "";

  if (isGold) {
    $(`#${folderElemId}-alarm-${alarmId}-qa-button`).removeAttr("hidden");
    $(`#${folderElemId}-alarm-${alarmId}-qa-button .gold-label`).removeAttr("hidden");
    setTimeout(() => $(`#${folderElemId}-alarm-${alarmId}-gold-label`).removeAttr("hidden"), 10);
  } else if (isSilver) {
    $(`#${folderElemId}-alarm-${alarmId}-qa-button`).removeAttr("hidden");
    $(`#${folderElemId}-alarm-${alarmId}-qa-button .silver-label`).removeAttr("hidden");
    setTimeout(() => $(`#${folderElemId}-alarm-${alarmId}-silver-label`).removeAttr("hidden"), 10);
  }

  let tpRadioId = `${folderElemId}-code-flow-${alarmId}-${codeFlowId}-tp-radio`;
  let fpRadioId = `${folderElemId}-code-flow-${alarmId}-${codeFlowId}-fp-radio`;

  return `
    <div class="code-flow bg-white p-3 border rounded" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}">
      <div class="d-flex pb-2 border-bottom">
        <div class="mt-1 col">
          <strong>
            <i class="fa-regular fa-bookmark"></i> Code Flow #<span>${codeFlowId + 1}</span>
            ${goldLabel}${silverLabel}
          </strong>
        </div>
        <div class="mt-1 d-flex">
          <div class="me-2">
            <input class="form-check-input me-1" type="checkbox" value="" id="${tpRadioId}">
            <label class="form-check-label" for="${tpRadioId}">
              <span class="text-success">True Pos</span>
            </label>
          </div>
          <div>
            <input class="form-check-input me-1" type="checkbox" value="" id="${fpRadioId}">
            <label class="form-check-label" for="${fpRadioId}">
              <span class="text-danger">False Pos</span>
            </label>
          </div>
        </div>
      </div>
      <div class="p-2 mt-2">
        <div class="d-flex mb-1 justify-content-between align-items-start">
          <strong>Source</strong>
          <a target="_blank" href="${sourceUrl}" class="badge rounded-pill text-bg-primary" style="text-decoration: none">${sourceFile}</a>
        </div>
        <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-source-snippet"></pre>
        <div class="d-flex mb-1 justify-content-between align-items-start">
          <strong>Sink</strong>
          <a target="_blank" href="${sinkUrl}" class="badge rounded-pill text-bg-primary" style="text-decoration: none">${sinkFile}</a>
        </div>
        <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-sink-snippet"></pre>
      </div>
      <div id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca" hidden="hidden">
        <div class="d-flex pb-2 border-bottom">
          <strong><i class="fa-regular fa-lightbulb"></i> Contextual Analysis:</strong>
        </div>
        <div class="p-2">
          <p>
            <strong>LLM Judgement: </strong>
            <span id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-judgement"></span>
          </p>
          <p>
            <strong>LLM Explanation: </strong>
            <span id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-explanation"></span>
          </p>
          <p><strong>Prompt: </strong></p>
          <pre class="p-2 border rounded bg-body-tertiary overflow-x" id="${folderElemId}-code-flow-${alarmId}-${codeFlowId}-ca-prompt"></pre>
        </div>
      </div>
      <div>
        <div class="d-flex pb-2 border-bottom">
          <strong><i class="fa fa-road-barrier"></i> Intermediate Steps (<span>${numIntermediateSteps}</span>):</strong>
        </div>
        <div class="list-group list-group-flush p-2">
          ${intermediateStepsHTML}
        </div>
      </div>
    </div>
  `;
}

function resultSarifAlarmToHTML(folder, alarmId, alarm, cveRow, fixedMethods, classLocs, funcLocs, hideIfNotTP) {
  let folderElemId = folderToElemId(folder);

  let numCodeFlows = 0;
  let codeFlowsHtml = "";
  let hasTP = false;
  if (!alarm["codeFlows"]) {
    numCodeFlows = 0;
  } else {
    numCodeFlows = alarm["codeFlows"].length;
    codeFlowsHtml = alarm["codeFlows"].map((codeFlow, codeFlowId) => {
      let fileLevelLabels = getCodeFlowFileLevelLabel(cveRow["cve_id"], codeFlow, fixedMethods);
      let methodLevelLabels = getCodeFlowMethodLevelLabel(cveRow["cve_id"], codeFlow, fixedMethods, classLocs, funcLocs);
      hasTP |= fileLevelLabels.some(v => v);
      return resultSarifCodeFlowToHTML(folder, alarmId, codeFlowId, codeFlow, cveRow, fileLevelLabels, methodLevelLabels);
    }).join("");
  }

  if (hideIfNotTP && !hasTP) {
    return ""
  } else {
    let collapseId = `${folderElemId}-alarm-${alarmId}-collapse`;

    return `
      <div class="highlight-toolbar mt-3 ps-3 pe-3 py-1 border rounded bg-body-tertiary" id="${folderElemId}-alarm-${alarmId}">
        <div class="d-flex w-100 align-items-center justify-content-between">
          <a class="mt-3 mb-3" data-bs-toggle="collapse" href="#${collapseId}" style="text-decoration: none" role="button" aria-expanded="true" aria-controls="${collapseId}">
            <strong><i class="fa fa-bell"></i> Alarm #${alarmId + 1} (#Code Flows: ${numCodeFlows})</strong>
            <span id="${folderElemId}-alarm-${alarmId}-gold-label" hidden="hidden">🥇</span>
            <span id="${folderElemId}-alarm-${alarmId}-silver-label" hidden="hidden">🥈</span>
          </a>
          <div class="btn-group btn-group-sm" role="group" aria-label="Small button group">
            <button type="button" class="btn btn-outline-primary">Remove Label</button>
            <button type="button" class="btn btn-outline-danger">Label as FP</button>
            <button type="button" class="btn btn-outline-success">Label as TP</button>
          </div>
        </div>
        <div class="collapse show" id="${collapseId}">
          <div class="code-flows d-flex pb-3 border-top pt-3">
            ${codeFlowsHtml}
          </div>
        </div>
      </div>
    `;
  }
}

const LIMIT = 200;

function resultSarifAlarmsToHTML(folder, alarms, cveRow, fixedMethods, classLocs, funcLocs) {
  return alarms.map((alarm, i) => {
    return resultSarifAlarmToHTML(folder, i, alarm, cveRow, fixedMethods, classLocs, funcLocs, i > LIMIT)
  }).join("");
}

function resultSarifAlarmsToQuickAccessPlaceholders(folder, alarms, cveRow) {
  let folderElemId = folderToElemId(folder);
  return alarms.map((alarm, alarmId) => {
    return `
      <li class="page-item" id="${folderElemId}-alarm-${alarmId}-qa-button" hidden="hidden">
        <a class="page-link" href="#${folderElemId}-alarm-${alarmId}" style="white-space: nowrap;">
          ${alarmId + 1}
          <span class="gold-label" hidden="hidden">🥇</span>
          <span class="silver-label" hidden="hidden">🥈</span>
          <span class="llm-label" hidden="hidden">🤖</span>
        </a>
      </li>
    `
  }).join("");
}

function renderResultSarif(folder, resultSarif, cveRow, fixedMethods) {
  fetchClassLocations(cveRow["project_slug"], folder["run_id"], (classLocs) => {
    fetchFuncLocations(cveRow["project_slug"], folder["run_id"], (funcLocs) => {
      let folderElemId = folderToElemId(folder);
      let results = resultSarif["runs"][0]["results"];

      // Load quick access placeholders
      $(`#${folderElemId}-quick-access`).html(resultSarifAlarmsToQuickAccessPlaceholders(folder, results, cveRow));

      // Load main results
      $(`#${folderElemId}-num-alerts`).text(results.length);
      $(`#${folderElemId}-alerts`).html(resultSarifAlarmsToHTML(folder, results, cveRow, fixedMethods, classLocs, funcLocs));

      // Load Source/Sink Snippets from Github
      loadSourceSinkSnippets(folder, resultSarif, cveRow);

      // Load posthoc-filtering result
      loadContextualAnalysisResult(folder, resultSarif, cveRow);
    })
  })
}

function loadTabContent(cveRow, folder, fixedMethods) {
  let dbName = cveRow["project_slug"];
  fetchJSON(`${OUTPUT_DIR}/${dbName}/${folder["run_id"]}/${folder["query"]}/results.sarif`, (resultSarif) => {
    if (resultSarif) {
      renderResultSarif(folder, resultSarif, cveRow, fixedMethods);
    }
  })
}

function loadResults(cveRow, fixedInfo) {
  // First load the tabs
  renderTabs();

  // Then load the tab contents
  let tab = getQueriedTabFromURL();
  if (!tab) {
    loadCommitsTabContent(cveRow);
    $(`#fix`).addClass("active").addClass("show").siblings().removeClass("active").removeClass("show");
  } else {
    let matchFolder = childFolders.find((childFolder) => folderToElemId(childFolder) == tab);
    if (matchFolder) {
      loadTabContent(cveRow, matchFolder, fixedMethods);
      let folderElemId = folderToElemId(matchFolder);
      $(`#${folderElemId}`).addClass("active").addClass("show").siblings().removeClass("active").removeClass("show");
    } else {
      loadCommitsTabContent(cveRow);
      $(`#fix`).addClass("active").addClass("show").siblings().removeClass("active").removeClass("show");
    }
  }
}

function renderMainContent(cveRow, fixedMethods) {
  let cve = cveRow["cve_id"];
  let project = cveRow["project_slug"];
  let [author, package] = project.split("_CVE-")[0].split("__");
  let tag = cveRow["github_tag"];

  // Render title
  $("#title-author").text(author);
  $("#title-package").text(package);
  $("#title-tag").text(tag);
  $("#title-cve-id").text(cve);
  $("#project-copy").attr("aria-data", project);

  // Render links
  $("#title-author").attr("href", `https://github.com/${cveRow['github_username']}`);
  $("#title-package").attr("href", `https://github.com/${cveRow['github_username']}/${cveRow['github_repository_name']}`);
  $("#title-tag").attr("href", `https://github.com/${cveRow['github_username']}/${cveRow['github_repository_name']}/tree/${tag}`);

  // Render NVD
  $("#title-nvd-link").attr("href", `https://nvd.nist.gov/vuln/detail/${cve}`);

  // Render fixing commits and methods
  let commits = cveRow["fix_commit_ids"].split(";");
  renderFixedCommits(cveRow, commits);
  renderFixedMethods(cve, cveRow['github_username'], cveRow['github_repository_name'], fixedMethods);

  // Query NVD description and render
  queryNVDDescription(cve, (description) => {
    $("#vulnerability-description").text(description);
  });

  // Fetch results
  loadResults(cveRow, fixedMethods)
}

function fold(list, init, func, onFinish) {
  function recurse(index, agg) {
    if (index < list.length) {
      let elem = list[index];
      func(elem, index, agg, (new_agg) => {
        recurse(index + 1, new_agg)
      })
    } else {
      onFinish(agg);
    }
  }

  recurse(0, init)
}

function fetchProjectInfo(callback) {
  fetchCSV(PROJECT_INFO_DIR, callback)
}

function fetchFixInfo(callback) {
  let cve = getQueriedCVEFromURL();
  if (cve) {
    fetchCSV(FIX_INFO_DIR, (csvContent) => {
      let fixedMethods = {}
      for (let i = 0; i < csvContent.length; i++) {
        let row = csvContent[i];
        if (row["cve_id"] != cve) {
          continue;
        }

        if (!fixedMethods[row["cve_id"]]) {
          fixedMethods[row["cve_id"]] = {
            "file_level": [],
            "method_level": [],
            "locations": [],
          }
        }

        let fileLevelLocation = `${row["file"]}`
        if (fileLevelLocation.indexOf("src/test/") >= 0) {
          continue;
        }
        let methodLevelLocation = `${row["file"]}:${row["class"]}:${row["method"]}`

        fixedMethods[row["cve_id"]]["file_level"].push(fileLevelLocation);
        fixedMethods[row["cve_id"]]["method_level"].push(methodLevelLocation);

        fixedMethods[row["cve_id"]]["locations"].push({
          "commit": row["commit"],
          "file": row["file"],
          "class": row["class"],
          "method": row["method"],
        });
      }

      callback(fixedMethods);
    })
  } else {
    callback(null);
  }
}

function fetchFile(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    success: (fileContent) => {
      callback(fileContent)
    },
    error: () => {
      callback(null)
    }
  })
}

function fetchCSV(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    success: (csvContent) => {
      let parsedResult = Papa.parse(csvContent, { header: true });
      let data = parsedResult.data;
      callback(data);
    }
  })
}

function fetchJSON(file, callback) {
  $.ajax({
    url: file,
    type: "GET",
    dataType: "json",
    success: (content) => {
      callback(content);
    },
    error: () => {
      callback(null);
    }
  })
}

function fetchChildDirectories(dir, callback) {
  $.ajax({
    url: dir,
    type: "GET",
    success: (data) => {
      const regexp = /<a href="(\S+)\/">/g;
      let results = [...data.matchAll(regexp)].map((d) => d[1]);
      callback(results);
    },
    error: () => {
      callback(null);
    },
  });
}

function fetchChildFiles(dir, callback) {
  $.ajax({
    url: dir,
    type: "GET",
    success: (data) => {
      const regexp = /<a href="(\S+\.\S+)">/g;
      let results = [...data.matchAll(regexp)].map((d) => d[1]);
      callback(results);
    },
    error: () => {
      callback(null);
    },
  });
}

function fetchOutputDirectory(dbName, callback) {
  fetchChildDirectories(`${OUTPUT_DIR}/${dbName}`, (runIds) => {
    if (runIds) {
      fold(runIds, [], (runId, _, results, cb1) => {
        fetchChildDirectories(`${OUTPUT_DIR}/${dbName}/${runId}`, (queries) => {
          if (queries) {
            fold(queries, results, (query, _, results, cb2) => {
              if (QUERY_NAMES[query]) {
                fetchChildFiles(`${OUTPUT_DIR}/${dbName}/${runId}/${query}`, (files) => {
                  if (files.indexOf("results.sarif") >= 0) {
                    cb2([...results, { "run_id": runId, "query": query }]);
                  } else {
                    cb2(results);
                  }
                })
              } else {
                cb2(results);
              }
            }, cb1);
          } else {
            cb1(results)
          }
        });
      }, callback);
    } else {
      callback([])
    }
  });
}

function fetchClassLocations(dbName, runId, callback) {
  fetchCSV(`${OUTPUT_DIR}/${dbName}/${runId}/fetch_class_locs/results.csv`, callback)
}

function fetchFuncLocations(dbName, runId, callback) {
  fetchCSV(`${OUTPUT_DIR}/${dbName}/${runId}/fetch_func_locs/results.csv`, callback)
}

function renderSearchBar(projectInfo) {
  $("#search-result-list").html(projectInfo.map(cveRow => {
    let cve = cveRow["cve_id"];
    if (!cveRow["cwe_id"]) {
      return "";
    }
    let project = cveRow["project_slug"];
    let [author, package] = project.split("_CVE-")[0].split("__");
    let tag = cveRow["github_tag"];
    let cweBadges = cveRow["cwe_id"].split(";").map(renderCWEBadge).join("");
    return `
      <a href="${generateHrefURL(null, cve)}" class="list-group-item list-group-item-action py-3 lh-tight" hidden="hidden">
        <div class="d-flex w-100 align-items-center justify-content-between">
          <strong class="mb-1 cve">${cve}</strong>
          <small class="cwes">${cweBadges}</small>
        </div>
        <div class="col-10 mb-1 small">
          <span class="author">${author}</span> / <span class="package">${package}</span> / <span class="tag">${tag}</span>
          <span class="project" hidden="hidden">${project}</span>
        </div>
      </a>
    `;
  }).join(""))
}

function matchSearchText(searchText, originalTexts) {
  let searchParts = searchText.split(" ").map(part => part.trim().toLowerCase()).filter(part => part != "");
  for (let part of searchParts) {
    let hasMatch = false;
    for (let originalText of originalTexts) {
      if (originalText.toLowerCase().indexOf(part) >= 0) {
        hasMatch = true;
      }
    }
    if (!hasMatch) {
      return false;
    }
  }
  return true;
}

function initializeSearchInputHandler() {
  const myModalEl = document.getElementById("search-modal");
  let collapseIsHidden = true;

  // When the modal is hidden, we collapse the
  myModalEl.addEventListener('hidden.bs.modal', event => {
    new bootstrap.Collapse("#search-result-collapse", { hide: true });
    collapseIsHidden = true;
    $("#search-input").blur();
  });

  // When the modal is shown, we focus on the search bar
  myModalEl.addEventListener('shown.bs.modal', event => {
    $("#search-input").focus();
  });

  // When the search bar is changed
  $('#search-input').on('input', function (event) {
    let searchText = $(this).val().toLowerCase();
    if (searchText == "") {
      new bootstrap.Collapse("#search-result-collapse", { hide: true });
      collapseIsHidden = true;
    } else {
      // Check
      if (collapseIsHidden) {
        new bootstrap.Collapse("#search-result-collapse", { show: true });
        collapseIsHidden = false;
      }

      // Do actual filtering
      $("#search-result-list a").each(function (index) {
        let elem = $(this);
        let allOriginalTextToSearch = [];

        // Add CVE
        let cve = elem.find(".cve").text().toLowerCase();
        allOriginalTextToSearch.push(cve);

        // Add CWE
        elem.find(".cwe span").each(function (index) {
          allOriginalTextToSearch.push($(this).text());
        });

        // Add Project, author, and tag
        allOriginalTextToSearch.push(elem.find(".package").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".author").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".tag").text().toLowerCase());
        allOriginalTextToSearch.push(elem.find(".project").text().toLowerCase());

        // Get final search result
        if (matchSearchText(searchText, allOriginalTextToSearch)) {
          elem.removeAttr("hidden");
        } else {
          elem.attr("hidden", "hidden");
        }
      })
    }
  });
}

function renderPage(projectInfo, fixInfo) {
  // Load sidebar
  renderSidebar(projectInfo);

  // Load search bar
  renderSearchBar(projectInfo);
  initializeSearchInputHandler();

  // Load main content
  let cve = getQueriedCVEFromURL();
  if (cve != null) {
    let maybeCveRows = projectInfo.filter((row) => row["cve_id"] == cve);
    if (maybeCveRows.length > 0) {
      let cveRow = maybeCveRows[0];
      renderMainContent(cveRow, fixInfo);
    }
  }
}

function loadPage() {
  fetchProjectInfo((projectInfo) => {
    fetchFixInfo((fixInfo) => {
      renderPage(projectInfo, fixInfo);
    })
  })
}

loadPage();
