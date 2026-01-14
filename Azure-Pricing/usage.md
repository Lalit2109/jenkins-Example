# Usage Guide - App Gateway Maintenance Pipeline

## What Does This Pipeline Do?

This pipeline helps you temporarily redirect traffic away from your Application Gateway during maintenance or patching. It's like putting up a "We're closed for maintenance" sign for your website.

**Two main actions:**
- **Maintenance Mode**: Redirects all traffic to a maintenance page (like Google.com) so you can work on your servers
- **Normal Mode**: Restores traffic back to your normal servers when you're done

## When Should You Use This?

- ✅ Before starting server patching or maintenance
- ✅ When you need to take backend servers offline temporarily
- ✅ During planned maintenance windows
- ✅ When you want to prevent users from accessing your application

## Quick Start - Running the Pipeline

### Step 1: Open the Pipeline

1. Go to **Azure DevOps** → **Pipelines**
2. Find and click on your pipeline (the one that uses `azure-pipelines.yml`)
3. Click **"Run pipeline"** button

### Step 2: Choose Your Settings

You'll see a form with these options:

**Environment** (Required)
- Choose which environment you want to modify:
  - `dev` or `dev002` - Development environments
  - `test` or `test002` - Testing environments  
  - `prod` or `prod002` - Production environments

**Action** (Required)
- **Maintenance** - Switch to maintenance mode (redirects traffic)
- **Normal** - Switch back to normal mode (restores traffic)

**Maintenance Redirect URL** (Only shown when Action is "Maintenance")
- The website where users will be redirected
- Default: `https://www.google.com`
- You can change this to your own maintenance page URL

### Step 3: Review and Run

1. Double-check your selections
2. Click **"Run"** button
3. The pipeline will start running

## What Happens Next?

### Stage 1: Validation
- The pipeline checks your settings
- Verifies the configuration file
- Shows you what routing rules will be affected
- **No changes are made yet** - this is just checking

### Stage 2: Approval Required ⚠️
- The pipeline will **pause** and wait for approval
- You'll see a message explaining what changes will be made
- **Someone with approval rights must approve** before the pipeline continues
- The approval will timeout after 15 minutes if no one approves

**To Approve:**
- Look for the approval notification in Azure DevOps
- Review the details shown in the approval message
- Click **"Approve"** to continue, or **"Reject"** to cancel

### Stage 3: Apply Changes
- Once approved, the pipeline will make the actual changes to your App Gateway
- This usually takes 1-2 minutes
- You'll see progress in the pipeline logs

### Stage 4: Notification
- The pipeline shows a summary of what was done
- Check the logs to see which routing rules were modified

## Common Scenarios

### Scenario 1: Starting a Maintenance Window

**Goal:** Redirect traffic away so you can patch servers

**Steps:**
1. Run pipeline
2. Select:
   - Environment: `prod` (or your production environment)
   - Action: `Maintenance`
   - Maintenance Redirect URL: `https://www.google.com` (or your maintenance page)
3. Wait for approval
4. Once approved, traffic will be redirected
5. **Now you can safely patch your servers**

### Scenario 2: Ending a Maintenance Window

**Goal:** Restore normal traffic after patching is complete

**Steps:**
1. Run pipeline again
2. Select:
   - Environment: `prod` (same as before)
   - Action: `Normal`
3. Wait for approval
4. Once approved, traffic will be restored to your servers
5. **Your application is back online!**

### Scenario 3: Working on a Specific Environment

**Example:** You want to work on `dev002` but not `dev`

**Steps:**
1. Run pipeline
2. Select:
   - Environment: `dev002` (not `dev`)
   - Action: `Maintenance`
3. Only `dev002` routing rules will be affected
4. `dev` will continue running normally

## Understanding the Output

### What You'll See in the Logs

**Validation Stage:**
```
Environment: prod
Action: Maintenance
Resource Group: rg-appgateway-prod
App Gateway: agw-prod
Maintenance Routing Rules: rule-api-prod, rule-web-prod
```

**After Changes:**
```
Operation completed successfully!
Routing rules updated: rule-api-prod, rule-web-prod
```

### What This Means

- **Routing Rules**: These are the specific paths/routes in your App Gateway that will be affected
- **Resource Group**: The Azure resource group where your App Gateway lives
- **App Gateway**: The name of your Application Gateway resource

## Important Notes

### ⚠️ Before Running

1. **Test First**: Always test in `dev` or `test` before using in `prod`
2. **Check Configuration**: Make sure your `environments.json` file has the correct routing rule names
3. **Coordinate**: Let your team know you're starting maintenance
4. **Have a Plan**: Know how long maintenance will take

### ⚠️ During Maintenance

1. **Don't Close the Pipeline**: Keep the pipeline page open so you can see progress
2. **Monitor Logs**: Watch the pipeline logs for any errors
3. **Time Limit**: Approval expires after 15 minutes - make sure someone is available to approve

### ⚠️ After Maintenance

1. **Verify**: Check that your application is working correctly after switching back to Normal
2. **Test**: Try accessing your application to make sure everything is restored
3. **Document**: Note what maintenance was performed

## Troubleshooting

### Problem: "Environment not found"
**Solution:** 
- Check that the environment name matches exactly what's in your `environments.json` file
- Available environments: dev, dev002, test, test002, prod, prod002

### Problem: "Routing rule not found"
**Solution:**
- The routing rule name in your config doesn't match the actual rule name in App Gateway
- Check your `environments.json` file and verify the rule names match exactly (case-sensitive)

### Problem: "Approval timeout"
**Solution:**
- The approval wasn't approved within 15 minutes
- Run the pipeline again and make sure someone is ready to approve

### Problem: "Permission denied"
**Solution:**
- The service connection (SPN) doesn't have the right permissions
- Contact your Azure administrator to grant `Contributor` role on the App Gateway resource group

### Problem: "Backend pool not found" (when switching to Normal)
**Solution:**
- The backend pool name in your config doesn't exist in App Gateway
- Check your `environments.json` file and verify the pool names match exactly

## Frequently Asked Questions

**Q: Can I run this for multiple environments at once?**  
A: No, run the pipeline separately for each environment you need to modify.

**Q: What happens if I cancel the pipeline?**  
A: If you cancel before approval, nothing changes. If you cancel after approval but during execution, the changes may be partially applied.

**Q: How long does it take?**  
A: Usually 2-5 minutes total (including approval time). The actual App Gateway update takes about 1-2 minutes.

**Q: Can I undo the changes?**  
A: Yes! Just run the pipeline again with the opposite action (Maintenance → Normal, or Normal → Maintenance).

**Q: Will this affect all my routing rules?**  
A: No, only the routing rules specified in your configuration file for that environment will be affected.

**Q: Do I need to be logged into Azure?**  
A: No, the pipeline uses a service connection (SPN) to authenticate automatically.

## Getting Help

If something goes wrong:

1. **Check the Pipeline Logs**: Look at the detailed logs in each stage
2. **Check Your Configuration**: Verify `environments.json` has correct values
3. **Check Permissions**: Ensure the service connection has proper access
4. **Contact Your Team**: Reach out to your infrastructure team or Azure administrator

## Quick Reference

### To Start Maintenance:
```
Pipeline → Run → Environment: [your-env] → Action: Maintenance → Run
```

### To End Maintenance:
```
Pipeline → Run → Environment: [your-env] → Action: Normal → Run
```

### Available Environments:
- `dev`, `dev002` - Development
- `test`, `test002` - Testing
- `prod`, `prod002` - Production

---

**Remember:** Always test in non-production environments first, and coordinate with your team before making changes to production!

