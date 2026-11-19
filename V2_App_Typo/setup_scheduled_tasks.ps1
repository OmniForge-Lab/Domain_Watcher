# Script PowerShell pour configurer les tâches planifiées du système de typosquatting
# Exécuter en tant qu'administrateur

param(
    [string]$AppPath = (Get-Location).Path,
    [string]$TaskName = "Typosquatting-Maintenance",
    [string]$ScheduleTime = "02:00",
    [switch]$Remove,
    [switch]$Test
)

# Vérifier les privilèges administrateur
if (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Error "Ce script doit être exécuté en tant qu'administrateur"
    exit 1
}

Write-Host "🔧 Configuration des tâches planifiées pour le système de typosquatting" -ForegroundColor Green
Write-Host "Répertoire de l'application: $AppPath" -ForegroundColor Cyan

# Fonction pour supprimer une tâche existante
function Remove-ExistingTask {
    param([string]$Name)
    
    try {
        $existingTask = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $Name -Confirm:$false
            Write-Host "✅ Tâche existante '$Name' supprimée" -ForegroundColor Yellow
        }
    }
    catch {
        Write-Host "ℹ️ Aucune tâche existante à supprimer" -ForegroundColor Gray
    }
}

# Fonction pour créer la tâche de maintenance
function Create-MaintenanceTask {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Time
    )
    
    # Supprimer la tâche existante si elle existe
    Remove-ExistingTask -Name $Name
    
    # Créer l'action
    $batchFile = Join-Path $Path "run_maintenance.bat"
    $action = New-ScheduledTaskAction -Execute $batchFile -WorkingDirectory $Path
    
    # Créer le déclencheur (quotidien)
    $trigger = New-ScheduledTaskTrigger -Daily -At $Time
    
    # Créer les paramètres
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable
    
    # Créer le principal (utilisateur système)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Enregistrer la tâche
    try {
        Register-ScheduledTask -TaskName $Name -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Maintenance quotidienne du système de détection de typosquatting"
        Write-Host "✅ Tâche '$Name' créée avec succès" -ForegroundColor Green
        Write-Host "   📅 Planifiée quotidiennement à $Time" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-Error "❌ Erreur lors de la création de la tâche: $($_.Exception.Message)"
        return $false
    }
}

# Fonction pour créer une tâche de surveillance en temps réel
function Create-MonitoringTask {
    param(
        [string]$Name,
        [string]$Path
    )
    
    $monitoringName = "$Name-Monitoring"
    Remove-ExistingTask -Name $monitoringName
    
    # Script de surveillance (toutes les heures)
    $monitoringScript = @"
@echo off
cd /d "$Path"
python maintenance_tasks.py --tasks transitions --quiet
"@
    
    $monitoringBatch = Join-Path $Path "run_monitoring.bat"
    $monitoringScript | Out-File -FilePath $monitoringBatch -Encoding ASCII
    
    # Créer l'action
    $action = New-ScheduledTaskAction -Execute $monitoringBatch -WorkingDirectory $Path
    
    # Créer le déclencheur (toutes les heures)
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 1) -RepetitionDuration (New-TimeSpan -Days 365)
    
    # Créer les paramètres
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -MultipleInstances IgnoreNew
    
    # Créer le principal
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount
    
    try {
        Register-ScheduledTask -TaskName $monitoringName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "Surveillance horaire des transitions d'état du système de typosquatting"
        Write-Host "✅ Tâche de surveillance '$monitoringName' créée" -ForegroundColor Green
        Write-Host "   🔄 Exécution toutes les heures" -ForegroundColor Cyan
        return $true
    }
    catch {
        Write-Error "❌ Erreur lors de la création de la tâche de surveillance: $($_.Exception.Message)"
        return $false
    }
}

# Fonction pour tester les tâches
function Test-Tasks {
    param([string]$Name)
    
    Write-Host "🧪 Test des tâches planifiées..." -ForegroundColor Yellow
    
    # Tester la tâche principale
    try {
        $task = Get-ScheduledTask -TaskName $Name -ErrorAction Stop
        Write-Host "✅ Tâche '$Name' trouvée" -ForegroundColor Green
        
        # Exécuter la tâche
        Start-ScheduledTask -TaskName $Name
        Write-Host "🚀 Tâche '$Name' démarrée" -ForegroundColor Green
        
        # Attendre un peu et vérifier le statut
        Start-Sleep -Seconds 5
        $taskInfo = Get-ScheduledTaskInfo -TaskName $Name
        Write-Host "📊 Statut: $($taskInfo.LastTaskResult)" -ForegroundColor Cyan
        
    }
    catch {
        Write-Error "❌ Erreur lors du test de la tâche: $($_.Exception.Message)"
    }
    
    # Tester la tâche de surveillance
    $monitoringName = "$Name-Monitoring"
    try {
        $monitoringTask = Get-ScheduledTask -TaskName $monitoringName -ErrorAction Stop
        Write-Host "✅ Tâche de surveillance '$monitoringName' trouvée" -ForegroundColor Green
    }
    catch {
        Write-Warning "⚠️ Tâche de surveillance non trouvée"
    }
}

# Fonction pour afficher le statut des tâches
function Show-TaskStatus {
    param([string]$Name)
    
    Write-Host "📋 Statut des tâches planifiées:" -ForegroundColor Cyan
    
    $tasks = @($Name, "$Name-Monitoring")
    
    foreach ($taskName in $tasks) {
        try {
            $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
            $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName
            
            Write-Host "\n🔧 $taskName:" -ForegroundColor White
            Write-Host "   État: $($task.State)" -ForegroundColor Gray
            Write-Host "   Dernière exécution: $($taskInfo.LastRunTime)" -ForegroundColor Gray
            Write-Host "   Résultat: $($taskInfo.LastTaskResult)" -ForegroundColor Gray
            Write-Host "   Prochaine exécution: $($taskInfo.NextRunTime)" -ForegroundColor Gray
        }
        catch {
            Write-Host "\n❌ $taskName: Non trouvée" -ForegroundColor Red
        }
    }
}

# Fonction principale
function Main {
    # Vérifier que le répertoire existe
    if (-not (Test-Path $AppPath)) {
        Write-Error "❌ Le répertoire '$AppPath' n'existe pas"
        exit 1
    }
    
    # Vérifier que les fichiers nécessaires existent
    $requiredFiles = @(
        "run_maintenance.bat",
        "maintenance_tasks.py",
        "config.py"
    )
    
    foreach ($file in $requiredFiles) {
        $filePath = Join-Path $AppPath $file
        if (-not (Test-Path $filePath)) {
            Write-Error "❌ Fichier requis manquant: $file"
            exit 1
        }
    }
    
    if ($Remove) {
        Write-Host "🗑️ Suppression des tâches planifiées..." -ForegroundColor Yellow
        Remove-ExistingTask -Name $TaskName
        Remove-ExistingTask -Name "$TaskName-Monitoring"
        Write-Host "✅ Tâches supprimées" -ForegroundColor Green
        return
    }
    
    if ($Test) {
        Test-Tasks -Name $TaskName
        Show-TaskStatus -Name $TaskName
        return
    }
    
    # Créer les tâches
    Write-Host "\n📅 Création de la tâche de maintenance quotidienne..." -ForegroundColor Yellow
    $maintenanceSuccess = Create-MaintenanceTask -Name $TaskName -Path $AppPath -Time $ScheduleTime
    
    Write-Host "\n🔄 Création de la tâche de surveillance horaire..." -ForegroundColor Yellow
    $monitoringSuccess = Create-MonitoringTask -Name $TaskName -Path $AppPath
    
    if ($maintenanceSuccess -and $monitoringSuccess) {
        Write-Host "\n✅ Configuration terminée avec succès!" -ForegroundColor Green
        Write-Host "\n📋 Résumé:" -ForegroundColor Cyan
        Write-Host "   • Maintenance quotidienne: $ScheduleTime" -ForegroundColor Gray
        Write-Host "   • Surveillance: Toutes les heures" -ForegroundColor Gray
        Write-Host "   • Utilisateur: SYSTEM" -ForegroundColor Gray
        
        Write-Host "\n🔧 Commandes utiles:" -ForegroundColor Cyan
        Write-Host "   • Tester: .\setup_scheduled_tasks.ps1 -Test" -ForegroundColor Gray
        Write-Host "   • Supprimer: .\setup_scheduled_tasks.ps1 -Remove" -ForegroundColor Gray
        Write-Host "   • Voir les tâches: Get-ScheduledTask -TaskName '*Typosquatting*'" -ForegroundColor Gray
        
        Show-TaskStatus -Name $TaskName
    }
    else {
        Write-Error "❌ Erreur lors de la configuration des tâches"
        exit 1
    }
}

# Exécution
Main