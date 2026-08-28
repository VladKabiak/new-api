import { useTranslation } from 'react-i18next'

import { Alert, AlertDescription } from '@/components/ui/alert'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import { SettingsSwitchField } from '../components/settings-form-layout'

export interface TrybitSettingsValues {
  TrybitEnabled: boolean
  TrybitApiKey: string
  TrybitSecretKey: string
  TrybitShopId: string
  TrybitUnitPrice: number
  TrybitMinTopUp: number
}

interface Props {
  values: TrybitSettingsValues
  onValueChange: <K extends keyof TrybitSettingsValues>(
    key: K,
    value: TrybitSettingsValues[K]
  ) => void
}

export function TrybitSettingsSection({ values, onValueChange }: Props) {
  const { t } = useTranslation()

  return (
    <div className='space-y-4 pt-4'>
      <div>
        <h3 className='text-lg font-medium'>{t('Trybit Crypto Gateway')}</h3>
        <p className='text-muted-foreground text-sm'>
          {t(
            'Cryptocurrency checkout — users are redirected to a Trybit invoice and credited once the callback is verified.'
          )}
        </p>
      </div>
      <Alert>
        <AlertDescription className='text-xs'>
          {t(
            'Obtain the API key, secret key and shop ID from the Trybit dashboard. The secret key verifies the callback signature, so keep both keys out of the client. In the Trybit project settings both fee sides must be set to the client, otherwise invoice creation is rejected rather than absorbing the fee.'
          )}
        </AlertDescription>
      </Alert>

      <SettingsSwitchField
        checked={values.TrybitEnabled}
        onCheckedChange={(v) => onValueChange('TrybitEnabled', v)}
        label={t('Enable Trybit')}
        className='py-0'
      />

      <div className='grid grid-cols-2 gap-4'>
        <div className='grid gap-1.5'>
          <Label>{t('API Key')}</Label>
          <Input
            type='password'
            value={values.TrybitApiKey}
            onChange={(event) =>
              onValueChange('TrybitApiKey', event.target.value)
            }
          />
        </div>
        <div className='grid gap-1.5'>
          <Label>{t('Secret Key')}</Label>
          <Input
            type='password'
            value={values.TrybitSecretKey}
            onChange={(event) =>
              onValueChange('TrybitSecretKey', event.target.value)
            }
          />
        </div>
      </div>

      <div className='grid grid-cols-3 gap-4'>
        <div className='grid gap-1.5'>
          <Label>{t('Shop ID')}</Label>
          <Input
            value={values.TrybitShopId}
            onChange={(event) =>
              onValueChange('TrybitShopId', event.target.value)
            }
          />
        </div>
        <div className='grid gap-1.5'>
          <Label>{t('Unit price (USD)')}</Label>
          <Input
            type='number'
            step={0.1}
            min={0}
            value={values.TrybitUnitPrice}
            onChange={(event) =>
              onValueChange(
                'TrybitUnitPrice',
                event.target.value === '' ? 0 : event.target.valueAsNumber
              )
            }
          />
        </div>
        <div className='grid gap-1.5'>
          <Label>{t('Minimum top-up quantity')}</Label>
          <Input
            type='number'
            min={1}
            value={values.TrybitMinTopUp}
            onChange={(event) =>
              onValueChange(
                'TrybitMinTopUp',
                event.target.value === '' ? 5 : event.target.valueAsNumber
              )
            }
          />
        </div>
      </div>
    </div>
  )
}
