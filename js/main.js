const awsTextArea = document.getElementById('aws-text');
const tfTextArea = document.getElementById('tf-text');
const convertToHcl = document.getElementById('convert-aws-to-tf');
const copyAwsText = document.getElementById('copy-aws-text');
const copyTfText = document.getElementById('copy-tf-text');
const IndentAwsText = document.getElementById('indent-aws-text');
const errorMessage = document.getElementById("error-message");

function validateJson() {
    try {
        const policy = JSON.parse(awsTextArea.value);

        if (!policy.Version) {
            throw new Error("Invalid policy format: 'Version' field is missing");
        }

        if (!policy.Statement || !Array.isArray(policy.Statement)) {
            throw new Error("Invalid policy format: 'Statement' field is missing or not an array");
        }

        const invalidFields = [];
        const iamPolicyFields = ["Effect","Action","NotAction","Resource","NotResource","Principal","NotPrincipal","Condition","Sid"];
        const iamPolicyConditionFields = [
            "StringEquals", "StringNotEquals", "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase",
            "StringLike", "StringNotLike", "NumericEquals", "NumericNotEquals", "NumericLessThan",
            "NumericLessThanEquals", "NumericGreaterThan", "NumericGreaterThanEquals",
            "DateEquals", "DateNotEquals", "DateLessThan", "DateLessThanEquals",
            "DateGreaterThan", "DateGreaterThanEquals", "Bool", "IpAddress", "NotIpAddress",
            "ArnEquals", "ArnNotEquals", "ArnLike", "ArnNotLike"
        ];
        for (const StatementsKey in policy.Statement) {
            for (const StatementKey in policy.Statement[StatementsKey]) {
                if (!iamPolicyFields.includes(StatementKey))
                    invalidFields.push(StatementKey);
                if (StatementKey === 'Condition') {
                    for (let conditionKey in policy.Statement.Condition) {
                        if (!iamPolicyConditionFields.includes(conditionKey))
                            invalidFields.push(conditionKey);
                    }
                }
            }
        }
        if (invalidFields.length > 0)
            throw new Error("Invalid policy fields: ".concat(invalidFields.join('')));

        errorMessage.innerHTML = "</br>";
        return policy;
    } catch (error) {
        errorMessage.textContent = error.message;
    }
}
function convertJsonToHcl(policy) {
    function indent(level) {
        return '  '.repeat(level);
    }

    function conditionToHcl(condition, indentLevel) {
        let result = ''
        for (let key in condition) {
            result += `${indent(indentLevel)}condition {\n`;
            result += `${indent(indentLevel + 1)}test = "${key}"\n`;
            for (let type in condition[key]) {
                result += `${indent(indentLevel + 1)}variable = "${type}"\n`;
                if (Array.isArray(condition[key][type]) && condition[key][type].length > 1) {
                    result += `${indent(indentLevel + 1)}values = [${condition[key][type].map(identifier => `\n${indent(indentLevel + 2)}"${identifier}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
                } else {
                    result += `${indent(indentLevel + 1)}values = ["${condition[key][type]}"]\n`;
                }
            }
            result += `${indent(indentLevel)}}\n`;
        }
        return result;
    }

    function principalsToHcl(principals, indentLevel) {
        let result = '';
        for (let principalType in principals) {
            result += `${indent(indentLevel)}principals {\n`;
            if (principals[principalType].includes("amazonaws.com"))
                result += `${indent(indentLevel + 1)}type = "Service"\n`;
            else
                result += `${indent(indentLevel + 1)}type = "AWS"\n`;
            if (Array.isArray(principals[principalType]) && principals[principalType].length > 1) {
                result += `${indent(indentLevel + 1)}identifiers = [${principals[principalType].map(identifier => `\n${indent(indentLevel + 2)}"${identifier}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
            } else {
                result += `${indent(indentLevel + 1)}identifiers = ["${principals[principalType]}"]\n`;
            }
            result += `${indent(indentLevel)}}\n`;
        }
        return result;
    }

    function statementToHcl(statement, indentLevel) {
        let result = `${indent(indentLevel)}statement {\n`;

        // Sid
        if (statement.Sid) {
            result += `${indent(indentLevel + 1)}sid = "${statement.Sid}"\n`;
        }

        // Effect
        if (statement.Effect) {
            result += `${indent(indentLevel + 1)}effect = "${statement.Effect}"\n`;
        }

        // Principals
        if (statement.Principal) {
            result += principalsToHcl(statement.Principal, indentLevel + 1);
        }

        // NotPrincipals
        if (statement.NotPrincipal) {
            result += principalsToHcl(statement.NotPrincipal, indentLevel + 1);
        }

        // Actions
        if (statement.Action) {
            if (Array.isArray(statement.Action) && statement.Action.length > 1) {
                result += `${indent(indentLevel + 1)}actions = [${statement.Action.map(action => `\n${indent(indentLevel + 2)}"${action}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
            } else {
                result += `${indent(indentLevel + 1)}actions = ["${statement.Action}"]\n`;
            }
        }

        // NotActions
        if (statement.NotAction) {
            if (Array.isArray(statement.NotAction) && statement.NotAction.length > 1) {
                result += `${indent(indentLevel + 1)}not_actions = [${statement.NotAction.map(action => `\n${indent(indentLevel + 2)}"${action}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
            } else {
                result += `${indent(indentLevel + 1)}not_actions = ["${statement.NotAction}"]\n`;
            }
        }

        // Resources
        if (statement.Resource) {
            if (Array.isArray(statement.Resource) && statement.Resource.length > 1) {
                result += `${indent(indentLevel + 1)}resources = [${statement.Resource.map(resource => `\n${indent(indentLevel + 2)}"${resource}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
            } else {
                result += `${indent(indentLevel + 1)}resources = ["${statement.Resource}"]\n`;
            }
        }

        // NotResources
        if (statement.NotResource) {
            if (Array.isArray(statement.NotResource && statement.NotResource.length > 1)) {
                result += `${indent(indentLevel + 1)}not_resources = [${statement.NotResource.map(resource => `\n${indent(indentLevel + 2)}"${resource}"`).join(", ")}\n${indent(indentLevel + 1)}]\n`;
            } else {
                result += `${indent(indentLevel + 1)}resources = ["${statement.NotResource}"]\n`;
            }
        }

        // Condition
        if (statement.Condition) {
            result += conditionToHcl(statement.Condition, indentLevel + 1);
        }

        result += `${indent(indentLevel)}}\n`;
        return result;
    }

    function policyToHcl(policy, indentLevel = 0) {
        let result = 'data "aws_iam_policy_document" "policy" {\n';
        for (let statement of policy.Statement) {
            result += statementToHcl(statement, indentLevel + 1);
        }
        result += `}`;
        return result;
    }

    return policyToHcl(policy);
}

convertToHcl.addEventListener('click', () => {
    try {
        const policy = validateJson();
        if (policy === undefined)
            return
        const convertedText = convertJsonToHcl(policy);
        tfTextArea.value = convertedText;
    } catch (error) {
        console.error(error.message);
    }
});

IndentAwsText.addEventListener('click', () => {
    const policy = validateJson();
    if (policy === undefined)
        return
    const formattedJSON = JSON.stringify(policy, null, 2);
    awsTextArea.value = formattedJSON;
});

copyAwsText.addEventListener('click', () => {
    const textarea = document.getElementById("aws-text");
    textarea.select();
    textarea.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(textarea.value)
});

copyTfText.addEventListener('click', () => {
    const textarea = document.getElementById("tf-text");
    textarea.select();
    textarea.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(textarea.value)
});

function updateLineNumbers(element) {
    const initialLines = 100
    let currentLines = initialLines;
    if (!element.load)
        currentLines = document.getElementById(element.id).value.split('\n').length;
    let lineNumbers = document.getElementById(element.id.concat('-line-numbers'));
    const totalLines = Math.max(currentLines, initialLines);
    lineNumbers.innerHTML = '';
    for (let i = 1; i <= totalLines; i++) {
        const lineDiv = document.createElement('div');
        lineDiv.textContent = i;
        lineNumbers.appendChild(lineDiv);
    }
}

function syncScroll(element) {
    const textarea = document.getElementById(element.id);
    const lineNumbers = document.getElementById(element.id.concat('-line-numbers'));
    lineNumbers.style.transform = `translateY(-${textarea.scrollTop}px)`;
}

function handleLineNumbers() {
    updateLineNumbers({ id: "aws-text", load: true});
    updateLineNumbers({ id: "tf-text", load: true});
}

window.addEventListener('resize', handleLineNumbers());